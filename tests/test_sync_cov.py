"""Tests for the rebrew sync module -- pure-function helpers."""

from types import SimpleNamespace
from typing import Any

from rebrew.sync import (
    _STATUS_BOOKMARK_CATEGORY,
    PullChange,
    PullResult,
    _fetch_mcp_tool,
    _ghidra_name_to_symbol,
    _is_generic_name,
    _is_meaningful_name,
    _parse_va,
    apply_commands_via_mcp,
    build_new_function_commands,
    build_size_sync_commands,
    build_sync_commands,
)

# ---------------------------------------------------------------------------
# _is_generic_name
# ---------------------------------------------------------------------------


class TestIsGenericName:
    """Tests for the _is_generic_name() helper."""

    def test_lowercase_generic(self) -> None:
        assert _is_generic_name("func_10006c00") is True

    def test_uppercase_generic(self) -> None:
        assert _is_generic_name("FUN_10006C00") is True

    def test_real_name(self) -> None:
        assert _is_generic_name("inflate_init") is False

    def test_underscore_prefix(self) -> None:
        assert _is_generic_name("_malloc") is False

    def test_empty_string(self) -> None:
        assert _is_generic_name("") is False

    def test_partial_match(self) -> None:
        """func_ prefix but non-hex suffix is not generic."""
        assert _is_generic_name("func_main_loop") is False

    def test_fun_prefix_hex(self) -> None:
        assert _is_generic_name("FUN_DEADBEEF") is True

    def test_func_prefix_mixed_case_hex(self) -> None:
        assert _is_generic_name("func_aAbBcCdD") is True


# ---------------------------------------------------------------------------
# _STATUS_BOOKMARK_CATEGORY
# ---------------------------------------------------------------------------


class TestStatusBookmarkCategory:
    """Tests for the _STATUS_BOOKMARK_CATEGORY mapping."""

    def test_exact(self) -> None:
        assert _STATUS_BOOKMARK_CATEGORY["EXACT"] == "rebrew/exact"

    def test_reloc(self) -> None:
        assert _STATUS_BOOKMARK_CATEGORY["RELOC"] == "rebrew/reloc"

    def test_matching(self) -> None:
        assert _STATUS_BOOKMARK_CATEGORY["MATCHING"] == "rebrew/matching"

    def test_matching_reloc(self) -> None:
        assert _STATUS_BOOKMARK_CATEGORY["MATCHING_RELOC"] == "rebrew/matching"

    def test_stub(self) -> None:
        assert _STATUS_BOOKMARK_CATEGORY["STUB"] == "rebrew/stub"

    def test_has_five_entries(self) -> None:
        assert len(_STATUS_BOOKMARK_CATEGORY) == 5


# ---------------------------------------------------------------------------
# build_sync_commands
# ---------------------------------------------------------------------------


def _make_entry(
    va: int = 0x10001000,
    name: str = "my_func",
    status: str = "RELOC",
    origin: str = "GAME",
    size: int = 100,
    cflags: str = "/O2 /Gd",
    symbol: str = "_my_func",
    marker_type: str = "FUNCTION",
    filepath: str = "src/server.dll/my_func.c",
    note: str = "",
) -> dict:
    return {
        "va": va,
        "name": name,
        "status": status,
        "origin": origin,
        "size": size,
        "cflags": cflags,
        "symbol": symbol,
        "marker_type": marker_type,
        "filepath": filepath,
        "note": note,
    }


class TestBuildSyncCommands:
    """Tests for build_sync_commands()."""

    def test_basic_commands(self) -> None:
        """One entry produces label + comment + bookmark."""
        entries = [_make_entry()]
        cmds = build_sync_commands(entries, "/server.dll")
        tools = [c["tool"] for c in cmds]
        assert "create-label" in tools
        assert "set-comment" in tools
        assert "set-bookmark" in tools

    def test_skips_generic_labels(self, capsys) -> None:
        """Generic names are skipped when skip_generic_labels=True."""
        entries = [_make_entry(name="func_10001000")]
        cmds = build_sync_commands(entries, "/server.dll", skip_generic_labels=True)
        label_cmds = [c for c in cmds if c["tool"] == "create-label"]
        assert len(label_cmds) == 0

    def test_includes_generic_labels_when_disabled(self) -> None:
        """Generic names are included when skip_generic_labels=False."""
        entries = [_make_entry(name="func_10001000")]
        cmds = build_sync_commands(entries, "/server.dll", skip_generic_labels=False)
        label_cmds = [c for c in cmds if c["tool"] == "create-label"]
        assert len(label_cmds) == 1

    def test_create_functions_flag(self) -> None:
        """create_functions=True prepends create-function commands."""
        entries = [_make_entry()]
        cmds = build_sync_commands(entries, "/server.dll", create_functions=True)
        assert cmds[0]["tool"] == "create-function"

    def test_no_create_functions_by_default(self) -> None:
        """create_functions=False (default) omits create-function."""
        entries = [_make_entry()]
        cmds = build_sync_commands(entries, "/server.dll", create_functions=False)
        create_cmds = [c for c in cmds if c["tool"] == "create-function"]
        assert len(create_cmds) == 0

    def test_iat_thunks_skipped(self) -> None:
        """VAs in iat_thunks are skipped for create-function."""
        entries = [_make_entry(va=0x10001000)]
        cmds = build_sync_commands(
            entries,
            "/server.dll",
            create_functions=True,
            iat_thunks={0x10001000},
        )
        create_cmds = [c for c in cmds if c["tool"] == "create-function"]
        assert len(create_cmds) == 0

    def test_comment_contains_status(self) -> None:
        """Comment includes status info."""
        entries = [_make_entry(status="EXACT")]
        cmds = build_sync_commands(entries, "/server.dll")
        comment_cmds = [c for c in cmds if c["tool"] == "set-comment"]
        assert len(comment_cmds) == 1
        assert "EXACT" in comment_cmds[0]["args"]["comment"]

    def test_bookmark_category(self) -> None:
        """Bookmark uses _STATUS_BOOKMARK_CATEGORY mapping."""
        entries = [_make_entry(status="RELOC")]
        cmds = build_sync_commands(entries, "/server.dll")
        bm_cmds = [c for c in cmds if c["tool"] == "set-bookmark"]
        assert len(bm_cmds) == 1
        assert bm_cmds[0]["args"]["category"] == "rebrew/reloc"

    def test_empty_entries(self) -> None:
        """No entries produces no commands."""
        cmds = build_sync_commands([], "/server.dll")
        assert cmds == []

    def test_multiple_entries_same_va(self) -> None:
        """Multiple entries at the same VA are grouped — one label from primary."""
        entries = [
            _make_entry(va=0x1000, name="game_pool_alloc", filepath="a.c"),
            _make_entry(va=0x1000, name="game_pool_alloc", filepath="b.c"),
        ]
        cmds = build_sync_commands(entries, "/server.dll")
        # Should use first entry's name for label
        label_cmds = [c for c in cmds if c["tool"] == "create-label"]
        assert len(label_cmds) == 1
        assert label_cmds[0]["args"]["labelName"] == "game_pool_alloc"


# ---------------------------------------------------------------------------
# build_size_sync_commands
# ---------------------------------------------------------------------------


class TestBuildSizeSyncCommands:
    """Tests for build_size_sync_commands()."""

    def test_expands_when_canonical_larger(self) -> None:
        """Generates command when canonical_size > ghidra_size."""
        registry = {
            0x1000: {
                "size_by_tool": {"ghidra": 50, "list": 80},
                "canonical_size": 80,
                "size_reason": "list larger",
            }
        }
        cmds = build_size_sync_commands(registry, "/server.dll")
        assert len(cmds) == 1
        assert cmds[0]["tool"] == "create-function"
        assert cmds[0]["args"]["address"] == "0x00001000"

    def test_no_command_when_equal(self) -> None:
        """No command when canonical_size == ghidra_size."""
        registry = {
            0x1000: {
                "size_by_tool": {"ghidra": 80, "list": 80},
                "canonical_size": 80,
                "size_reason": "",
            }
        }
        cmds = build_size_sync_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_no_command_when_canonical_smaller(self) -> None:
        """No command when canonical_size < ghidra_size."""
        registry = {
            0x1000: {
                "size_by_tool": {"ghidra": 80},
                "canonical_size": 50,
                "size_reason": "",
            }
        }
        cmds = build_size_sync_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_skips_iat_thunks(self) -> None:
        """IAT thunk VAs are skipped."""
        registry = {
            0x1000: {
                "size_by_tool": {"ghidra": 50},
                "canonical_size": 80,
                "size_reason": "",
            }
        }
        cmds = build_size_sync_commands(registry, "/server.dll", iat_thunks={0x1000})
        assert len(cmds) == 0

    def test_skips_zero_sizes(self) -> None:
        """Entries with zero canonical or ghidra size are skipped."""
        registry = {
            0x1000: {
                "size_by_tool": {"ghidra": 0},
                "canonical_size": 80,
                "size_reason": "",
            }
        }
        cmds = build_size_sync_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_empty_registry(self) -> None:
        cmds = build_size_sync_commands({}, "/server.dll")
        assert cmds == []


# ---------------------------------------------------------------------------
# build_new_function_commands
# ---------------------------------------------------------------------------


class TestBuildNewFunctionCommands:
    """Tests for build_new_function_commands()."""

    def test_list_only_function(self) -> None:
        """Generates command for function detected by list but not ghidra."""
        registry = {
            0x2000: {
                "detected_by": ["list"],
                "canonical_size": 64,
                "size_by_tool": {"list": 64},
            }
        }
        cmds = build_new_function_commands(registry, "/server.dll")
        assert len(cmds) == 1
        assert cmds[0]["tool"] == "create-function"

    def test_both_detected_no_command(self) -> None:
        """No command when both list and ghidra detected the function."""
        registry = {
            0x2000: {
                "detected_by": ["list", "ghidra"],
                "canonical_size": 64,
                "size_by_tool": {"list": 64, "ghidra": 64},
            }
        }
        cmds = build_new_function_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_ghidra_only_no_command(self) -> None:
        """No command when only ghidra detected the function."""
        registry = {
            0x2000: {
                "detected_by": ["ghidra"],
                "canonical_size": 64,
                "size_by_tool": {"ghidra": 64},
            }
        }
        cmds = build_new_function_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_skips_zero_canonical_size(self) -> None:
        """Entries with zero canonical size are skipped."""
        registry = {
            0x2000: {
                "detected_by": ["list"],
                "canonical_size": 0,
                "size_by_tool": {"list": 0},
            }
        }
        cmds = build_new_function_commands(registry, "/server.dll")
        assert len(cmds) == 0

    def test_skips_iat_thunks(self) -> None:
        """IAT thunk VAs are skipped."""
        registry = {
            0x2000: {
                "detected_by": ["list"],
                "canonical_size": 64,
                "size_by_tool": {"list": 64},
            }
        }
        cmds = build_new_function_commands(registry, "/server.dll", iat_thunks={0x2000})
        assert len(cmds) == 0

    def test_empty_registry(self) -> None:
        cmds = build_new_function_commands({}, "/server.dll")
        assert cmds == []


class _FakeHTTPError(Exception):
    pass


class _FakeResponse:
    def __init__(self, text: str, headers: dict[str, str] | None = None) -> None:
        self.text = text
        self.headers = headers or {}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        import json

        return json.loads(self.text)


class _FakeClient:
    def __init__(self, responses: list[_FakeResponse], timeout: float) -> None:
        self._responses = responses
        self._index = 0
        self.timeout = timeout

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None

    def post(self, endpoint: str, json: dict, headers: dict[str, str]) -> _FakeResponse:
        _ = endpoint, json, headers
        response = self._responses[self._index]
        self._index += 1
        return response


class TestApplyCommandsViaMcp:
    def test_success_counts_jsonrpc_result(self, monkeypatch) -> None:
        responses = [
            _FakeResponse('{"jsonrpc":"2.0","id":0,"result":{}}', {"mcp-session-id": "abc"}),
            _FakeResponse('{"jsonrpc":"2.0","result":{}}'),
            _FakeResponse('{"jsonrpc":"2.0","id":1,"result":{}}'),
        ]
        monkeypatch.setattr(
            "rebrew.sync.httpx.Client", lambda timeout: _FakeClient(responses, timeout)
        )
        monkeypatch.setattr("rebrew.sync.httpx.HTTPError", _FakeHTTPError)

        commands = [
            {
                "tool": "create-label",
                "args": {
                    "programPath": "/server.dll",
                    "addressOrSymbol": "0x00001000",
                    "labelName": "game_pool_alloc",
                },
            }
        ]
        success, errors = apply_commands_via_mcp(commands)
        assert success == 1
        assert errors == 0

    def test_jsonrpc_error_counts_as_failure(self, monkeypatch) -> None:
        responses = [
            _FakeResponse('{"jsonrpc":"2.0","id":0,"result":{}}', {"mcp-session-id": "abc"}),
            _FakeResponse('{"jsonrpc":"2.0","result":{}}'),
            _FakeResponse('{"jsonrpc":"2.0","id":1,"error":{"message":"boom"}}'),
        ]
        monkeypatch.setattr(
            "rebrew.sync.httpx.Client", lambda timeout: _FakeClient(responses, timeout)
        )
        monkeypatch.setattr("rebrew.sync.httpx.HTTPError", _FakeHTTPError)

        commands = [
            {
                "tool": "create-label",
                "args": {
                    "programPath": "/server.dll",
                    "addressOrSymbol": "0x00001000",
                    "labelName": "game_pool_alloc",
                },
            }
        ]
        success, errors = apply_commands_via_mcp(commands)
        assert success == 0
        assert errors == 1


class TestBuildSyncCommandsData:
    def test_skips_create_function_for_data(self) -> None:
        entries = [
            {
                "va": 0x1000,
                "name": "g_foo",
                "status": "EXACT",
                "origin": "GAME",
                "size": 4,
                "cflags": "",
                "symbol": "g_foo",
                "marker_type": "DATA",
                "filepath": "a.c",
            }
        ]
        # Even with create_functions=True, it should skip
        cmds = build_sync_commands(entries, "/test", create_functions=True)
        assert len([c for c in cmds if c["tool"] == "create-function"]) == 0

    def test_syncs_data_scan(self) -> None:
        from collections import namedtuple

        GlobalEntry = namedtuple(
            "GlobalEntry", ["name", "va", "type_str", "section", "declared_in"]
        )
        ScanResult = namedtuple("ScanResult", ["globals", "data_annotations"])

        data_scan = ScanResult(
            globals={"g_foo": GlobalEntry("g_foo", 0x2000, "int", ".bss", ["a.c"])},
            data_annotations=[
                {
                    "va": "0x00003000",
                    "name": "s_hello",
                    "size": 10,
                    "section": ".data",
                    "origin": "GAME",
                    "note": "hi",
                    "filepath": "a.c",
                }
            ],
        )

        cmds = build_sync_commands([], "/test", data_scan=data_scan)
        labels = [c for c in cmds if c["tool"] == "create-label"]
        comments = [c for c in cmds if c["tool"] == "set-comment"]
        bookmarks = [c for c in cmds if c["tool"] == "set-bookmark"]

        assert len(labels) == 2
        assert labels[0]["args"]["addressOrSymbol"] == "0x00002000"
        assert labels[0]["args"]["labelName"] == "g_foo"
        assert labels[1]["args"]["addressOrSymbol"] == "0x00003000"
        assert labels[1]["args"]["labelName"] == "s_hello"

        assert len(comments) == 2
        assert "Type: int" in comments[0]["args"]["comment"]
        assert "Section: .bss" in comments[0]["args"]["comment"]
        assert "Note: hi" in comments[1]["args"]["comment"]
        assert "Origin: GAME" in comments[1]["args"]["comment"]

        assert len(bookmarks) == 2
        assert bookmarks[0]["args"]["category"] == "rebrew/data"
        assert "Global: int g_foo" in bookmarks[0]["args"]["comment"]

    def test_syncs_structs(self) -> None:
        cmds = build_sync_commands(
            [], "/test", structs=["struct Foo { int x; };", "typedef struct { int y; } Bar;"]
        )
        struct_ops = [c for c in cmds if c["tool"] == "parse-c-structure"]

        assert len(struct_ops) == 2
        assert struct_ops[0]["args"]["cCode"] == "struct Foo { int x; };"
        assert struct_ops[1]["args"]["cCode"] == "typedef struct { int y; } Bar;"


class TestBuildSyncCommandsSignatures:
    def test_syncs_signatures(self) -> None:
        entries = [
            {
                "va": 0x1000,
                "name": "my_func",
                "status": "EXACT",
                "origin": "GAME",
                "size": 10,
                "cflags": "",
                "symbol": "my_func",
                "marker_type": "FUNCTION",
                "filepath": "a.c",
            }
        ]
        sigs = [{"va_hex": "0x00001000", "signature": "int __cdecl my_func(int a, char *b);"}]

        cmds = build_sync_commands(entries, "/test", signatures=sigs)
        sig_ops = [c for c in cmds if c["tool"] == "set-function-prototype"]

        assert len(sig_ops) == 1
        assert sig_ops[0]["args"]["addressOrSymbol"] == "0x00001000"
        assert sig_ops[0]["args"]["prototype"] == "int __cdecl my_func(int a, char *b);"


# ---------------------------------------------------------------------------
# _parse_va
# ---------------------------------------------------------------------------


class TestParseVA:
    """Tests for the _parse_va() helper."""

    def test_hex_string(self) -> None:
        assert _parse_va("0x10001000") == 0x10001000

    def test_hex_string_uppercase(self) -> None:
        assert _parse_va("0x1000ABCD") == 0x1000ABCD

    def test_int_passthrough(self) -> None:
        assert _parse_va(0x10001000) == 0x10001000

    def test_decimal_string(self) -> None:
        assert _parse_va("268439552") == 268439552

    def test_none_returns_none(self) -> None:
        assert _parse_va(None) is None

    def test_invalid_hex_returns_none(self) -> None:
        assert _parse_va("0xGGGG") is None

    def test_invalid_string_returns_none(self) -> None:
        assert _parse_va("not_a_number") is None

    def test_empty_string_returns_none(self) -> None:
        assert _parse_va("") is None

    def test_zero(self) -> None:
        assert _parse_va(0) == 0

    def test_float_truncates_to_int(self) -> None:
        assert _parse_va(3.14) == 3


# ---------------------------------------------------------------------------
# _is_meaningful_name
# ---------------------------------------------------------------------------


class TestIsMeaningfulName:
    """Tests for the _is_meaningful_name() helper."""

    def test_real_name(self) -> None:
        assert _is_meaningful_name("inflate_init") is True

    def test_underscore_prefix(self) -> None:
        assert _is_meaningful_name("_malloc") is True

    def test_empty_string(self) -> None:
        assert _is_meaningful_name("") is False

    def test_fun_prefix(self) -> None:
        assert _is_meaningful_name("FUN_10006C00") is False

    def test_dat_prefix(self) -> None:
        assert _is_meaningful_name("DAT_10008000") is False

    def test_func_generic(self) -> None:
        assert _is_meaningful_name("func_10006c00") is False

    def test_switchdata_prefix(self) -> None:
        assert _is_meaningful_name("switchdata_100abc") is False

    def test_switchdata_exact(self) -> None:
        assert _is_meaningful_name("switchdata") is False

    def test_dat_short(self) -> None:
        """DAT_ prefix is always non-meaningful regardless of suffix."""
        assert _is_meaningful_name("DAT_") is False

    def test_meaningful_with_fun_substring(self) -> None:
        """Name containing FUN_ in the middle is still meaningful."""
        assert _is_meaningful_name("setup_FUN_handler") is True


# ---------------------------------------------------------------------------
# PullChange / PullResult dataclasses
# ---------------------------------------------------------------------------


class TestPullChange:
    """Tests for the PullChange dataclass."""

    def test_to_dict_basic(self) -> None:
        c = PullChange(
            va=0x10001000,
            field="SYMBOL",
            local_value="func_10001000",
            ghidra_value="game_init",
            filepath="game_init.c",
            action="update",
        )
        d = c.to_dict()
        assert d["va"] == "0x10001000"
        assert d["field"] == "SYMBOL"
        assert d["local"] == "func_10001000"
        assert d["ghidra"] == "game_init"
        assert d["file"] == "game_init.c"
        assert d["action"] == "update"
        assert "reason" not in d

    def test_to_dict_with_reason(self) -> None:
        c = PullChange(
            va=0x10001000,
            field="SYMBOL",
            local_value="my_func",
            ghidra_value="their_func",
            filepath="my_func.c",
            action="conflict",
            reason="both local and Ghidra have meaningful names",
        )
        d = c.to_dict()
        assert d["action"] == "conflict"
        assert d["reason"] == "both local and Ghidra have meaningful names"

    def test_va_formatting(self) -> None:
        """VA should be zero-padded to 8 hex digits."""
        c = PullChange(
            va=0x1000,
            field="SYMBOL",
            local_value="a",
            ghidra_value="b",
            filepath="a.c",
            action="update",
        )
        assert c.to_dict()["va"] == "0x00001000"


class TestPullResult:
    """Tests for the PullResult dataclass."""

    def test_defaults(self) -> None:
        r = PullResult()
        assert r.changes == []
        assert r.updated == 0
        assert r.skipped == 0
        assert r.conflicts == 0

    def test_to_dict_empty(self) -> None:
        r = PullResult()
        d = r.to_dict()
        assert d == {"updated": 0, "skipped": 0, "conflicts": 0, "changes": []}

    def test_to_dict_with_changes(self) -> None:
        c = PullChange(
            va=0x10001000,
            field="SYMBOL",
            local_value="old",
            ghidra_value="new",
            filepath="f.c",
            action="update",
        )
        r = PullResult(changes=[c], updated=1)
        d = r.to_dict()
        assert d["updated"] == 1
        assert len(d["changes"]) == 1
        assert d["changes"][0]["action"] == "update"

    def test_to_dict_conflicts(self) -> None:
        c = PullChange(
            va=0x10001000,
            field="SYMBOL",
            local_value="mine",
            ghidra_value="theirs",
            filepath="f.c",
            action="conflict",
            reason="both meaningful",
        )
        r = PullResult(changes=[c], conflicts=1)
        d = r.to_dict()
        assert d["conflicts"] == 1
        assert d["changes"][0]["reason"] == "both meaningful"


# ---------------------------------------------------------------------------
# _fetch_mcp_tool
# ---------------------------------------------------------------------------


class _FakeMCPResponse:
    """Fake HTTP response for _fetch_mcp_tool tests."""

    def __init__(self, status_code: int, body: dict[str, Any]) -> None:
        import json as _json

        self.status_code = status_code
        self._body = body
        self.headers: dict[str, str] = {"content-type": "application/json"}
        self.text = _json.dumps(body) if body else ""

    def json(self) -> dict[str, Any]:
        return self._body


class _FakeMCPClient:
    """Fake HTTP client that returns a preset response for any POST."""

    def __init__(self, response: _FakeMCPResponse) -> None:
        self._response = response

    def post(
        self, endpoint: str, json: dict, headers: dict[str, str] | None = None
    ) -> _FakeMCPResponse:
        _ = endpoint, json, headers
        return self._response


class TestFetchMcpTool:
    """Tests for the _fetch_mcp_tool() helper."""

    def test_successful_parse(self) -> None:
        import json as _json

        body = {
            "result": {
                "content": [
                    {"type": "text", "text": _json.dumps([{"name": "foo", "va": "0x1000"}])}
                ]
            }
        }
        client = _FakeMCPClient(_FakeMCPResponse(200, body))
        result = _fetch_mcp_tool(client, "http://fake/mcp", "get-functions", {}, 1)
        assert len(result) == 1
        assert result[0]["name"] == "foo"

    def test_non_200_returns_empty(self) -> None:
        client = _FakeMCPClient(_FakeMCPResponse(500, {}))
        result = _fetch_mcp_tool(client, "http://fake/mcp", "get-functions", {}, 1)
        assert result == []

    def test_no_result_key_returns_empty(self) -> None:
        client = _FakeMCPClient(_FakeMCPResponse(200, {"error": "boom"}))
        result = _fetch_mcp_tool(client, "http://fake/mcp", "get-functions", {}, 1)
        assert result == []

    def test_no_text_content_returns_empty(self) -> None:
        body = {"result": {"content": [{"type": "image", "data": "abc"}]}}
        client = _FakeMCPClient(_FakeMCPResponse(200, body))
        result = _fetch_mcp_tool(client, "http://fake/mcp", "get-functions", {}, 1)
        assert result == []

    def test_invalid_json_in_text_returns_empty(self) -> None:
        body = {"result": {"content": [{"type": "text", "text": "not valid json{{{"}]}}
        client = _FakeMCPClient(_FakeMCPResponse(200, body))
        result = _fetch_mcp_tool(client, "http://fake/mcp", "get-functions", {}, 1)
        assert result == []


# ---------------------------------------------------------------------------
# build_sync_commands — NOTE as pre-comment
# ---------------------------------------------------------------------------


class TestBuildSyncCommandsNote:
    """Tests for NOTE being pushed as a pre-comment."""

    def test_note_generates_pre_comment(self) -> None:
        entries = [_make_entry(note="This function handles player init")]
        cmds = build_sync_commands(entries, "/server.dll")
        pre_comments = [
            c for c in cmds if c["tool"] == "set-comment" and c["args"].get("commentType") == "pre"
        ]
        assert len(pre_comments) == 1
        assert pre_comments[0]["args"]["comment"] == "This function handles player init"

    def test_empty_note_no_pre_comment(self) -> None:
        entries = [_make_entry()]
        cmds = build_sync_commands(entries, "/server.dll")
        pre_comments = [
            c for c in cmds if c["tool"] == "set-comment" and c["args"].get("commentType") == "pre"
        ]
        assert len(pre_comments) == 0

    def test_plate_comment_still_generated(self) -> None:
        """NOTE pre-comment should not replace the plate metadata comment."""
        entries = [_make_entry(note="some note")]
        cmds = build_sync_commands(entries, "/server.dll")
        plate_comments = [
            c
            for c in cmds
            if c["tool"] == "set-comment" and c["args"].get("commentType") == "plate"
        ]
        assert len(plate_comments) == 1
        assert "[rebrew]" in plate_comments[0]["args"]["comment"]


# ---------------------------------------------------------------------------
# _ghidra_name_to_symbol
# ---------------------------------------------------------------------------


class TestGhidraNameToSymbol:
    """Tests for the _ghidra_name_to_symbol() helper."""

    def test_already_has_underscore(self) -> None:
        """Name already starting with _ is returned unchanged."""
        assert _ghidra_name_to_symbol("_AllocGameObject", {}) == "_AllocGameObject"

    def test_empty_string(self) -> None:
        assert _ghidra_name_to_symbol("", {}) == ""

    def test_adds_underscore_for_cdecl_entry(self) -> None:
        """When entry has symbol with _ prefix, adds _ to Ghidra name."""
        entry = {"symbol": "_old_func", "cflags": "/O2 /Gd"}
        assert _ghidra_name_to_symbol("AllocGameObject", entry) == "_AllocGameObject"

    def test_no_underscore_for_stdcall(self) -> None:
        """When CFLAGS contain /Gz (stdcall), no underscore is added."""
        entry = {"symbol": "", "cflags": "/O2 /Gz"}
        assert _ghidra_name_to_symbol("WinMainCRTStartup", entry) == "WinMainCRTStartup"

    def test_default_adds_underscore(self) -> None:
        """When no hints are available, default to adding _ (cdecl is most common)."""
        assert _ghidra_name_to_symbol("AllocGameObject", {}) == "_AllocGameObject"

    def test_cfg_symbol_prefix_takes_priority(self) -> None:
        """cfg.symbol_prefix overrides entry-level heuristics."""
        cfg = SimpleNamespace(symbol_prefix="_")
        assert _ghidra_name_to_symbol("AllocGameObject", {}, cfg=cfg) == "_AllocGameObject"

    def test_cfg_empty_symbol_prefix(self) -> None:
        """cfg.symbol_prefix='' (e.g. x86_64) means no prefix added from config."""
        cfg = SimpleNamespace(symbol_prefix="")
        # Falls through to entry-level heuristic — default adds _
        assert _ghidra_name_to_symbol("AllocGameObject", {}, cfg=cfg) == "_AllocGameObject"

    def test_annotation_object_entry(self) -> None:
        """Works with Annotation-like objects (attribute access, not dict)."""
        entry = SimpleNamespace(symbol="_my_func", cflags="/O2 /Gd")
        assert _ghidra_name_to_symbol("NewName", entry) == "_NewName"

    def test_generic_local_symbol_no_underscore(self) -> None:
        """When local symbol is generic (no _), still default-adds _ for cdecl."""
        entry = {"symbol": "func_10001000", "cflags": "/O2 /Gd"}
        assert _ghidra_name_to_symbol("GameInit", entry) == "_GameInit"


# ---------------------------------------------------------------------------
# _is_meaningful_name — thunk_ prefix
# ---------------------------------------------------------------------------


class TestIsMeaningfulNameThunk:
    """Tests for thunk_ prefix filtering in _is_meaningful_name()."""

    def test_thunk_prefix(self) -> None:
        assert _is_meaningful_name("thunk_FUN_10001000") is False

    def test_thunk_bare(self) -> None:
        assert _is_meaningful_name("thunk_") is False

    def test_not_thunk(self) -> None:
        """Names that happen to contain 'thunk' elsewhere are meaningful."""
        assert _is_meaningful_name("setup_thunk_handler") is True
