"""Tests for Ghidra parameter-name sync (H7): pull + merge-safe apply."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from rebrew.ghidra.params import _TYPE_KEYWORDS, apply_param_names, param_names_from_proto


class TestParamNamesFromProto:
    def test_named_and_unnamed(self) -> None:
        assert param_names_from_proto("int f(int a, char *b)") == ["a", "b"]
        assert param_names_from_proto("int f(int, char *)") == ["", ""]

    def test_pointer_names(self) -> None:
        assert param_names_from_proto("int f(char **pp, int *p)") == ["pp", "p"]

    def test_void_and_empty(self) -> None:
        assert param_names_from_proto("int f(void)") == []
        assert param_names_from_proto("int f()") == []

    def test_function_pointer_unsafe(self) -> None:
        assert param_names_from_proto("int f(int (*cb)(int))") is None

    def test_garbage(self) -> None:
        assert param_names_from_proto("not a proto") is None


class TestApplyParamNames:
    def test_fills_unnamed_only(self) -> None:
        src = "int f(int a, char *) { return a; }"
        out = apply_param_names(src, "f", ["a", "buf"])
        assert out == "int f(int a, char * buf) { return a; }"

    def test_named_params_never_overwritten(self) -> None:
        src = "int f(char *s, int) { return 0; }"
        out = apply_param_names(src, "f", ["str", "n"])
        assert out == "int f(char *s, int n) { return 0; }"
        assert "str" not in out  # s kept

    def test_all_named_no_change(self) -> None:
        assert apply_param_names("int f(int a, int b) { return a + b; }", "f", ["x", "y"]) is None

    def test_arity_mismatch_skipped(self) -> None:
        assert apply_param_names("int f(int a) { return a; }", "f", ["x", "y"]) is None

    def test_function_pointer_skipped(self) -> None:
        assert apply_param_names("int f(int (*cb)(int)) { return 0; }", "f", ["cb"]) is None

    def test_multiline_signature(self) -> None:
        src = "int g(\n    int,\n    int b\n) { return 0; }"
        out = apply_param_names(src, "g", ["x", "y"])
        assert out is not None
        assert "int x" in out
        assert "int b" in out  # b untouched

    def test_unknown_function_skipped(self) -> None:
        assert apply_param_names("int f(void) { return 0; }", "other", []) is None


class TestPullParamsMcp:
    """pull_params against a mocked MCP endpoint."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        return SimpleNamespace(reversed_dir=tmp_path, metadata_dir=tmp_path)

    def _patch_mcp(self, monkeypatch, signature: str) -> None:
        def _fake_init(client: Any, endpoint: str) -> str:
            return "sess-x"

        def _fake_fetch(
            client: Any, endpoint: str, tool: str, args: dict, rid: int, session_id: str = ""
        ) -> Any:
            if tool == "get-decompilation":
                return {"signature": signature}
            return None

        class _FakeClient:
            def __init__(self, timeout: float) -> None:
                pass

            def __enter__(self) -> _FakeClient:
                return self

            def __exit__(self, *exc: object) -> None:
                return None

        monkeypatch.setattr("rebrew.ghidra.commands.init_mcp_session", _fake_init)
        monkeypatch.setattr("rebrew.ghidra.commands.fetch_mcp_tool_raw", _fake_fetch)
        monkeypatch.setattr("rebrew.ghidra.commands.httpx.Client", _FakeClient)

    def test_pull_names_unnamed_params(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.ghidra.commands import pull_params

        src = tmp_path / "f.c"
        src.write_text("int f(int, char *) { return 0; }\n", encoding="utf-8")
        entries = [
            {
                "marker_type": "FUNCTION",
                "va": 0x401000,
                "name": "f",
                "filepath": "f.c",
            }
        ]
        self._patch_mcp(monkeypatch, "int f(int count, char *buf)")
        n = pull_params(entries, self._cfg(tmp_path), "http://mcp", "/prog", dry_run=False)
        assert n == 1
        assert src.read_text(encoding="utf-8") == "int f(int count, char * buf) { return 0; }\n"

    def test_pull_dry_run_does_not_write(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.ghidra.commands import pull_params

        src = tmp_path / "f.c"
        src.write_text("int f(int) { return 0; }\n", encoding="utf-8")
        entries = [{"marker_type": "FUNCTION", "va": 0x401000, "name": "f", "filepath": "f.c"}]
        self._patch_mcp(monkeypatch, "int f(int count)")
        n = pull_params(entries, self._cfg(tmp_path), "http://mcp", "/prog", dry_run=True)
        assert n == 1
        assert src.read_text(encoding="utf-8") == "int f(int) { return 0; }\n"  # untouched

    def test_pull_arity_mismatch_skipped(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.ghidra.commands import pull_params

        src = tmp_path / "f.c"
        src.write_text("int f(int, int) { return 0; }\n", encoding="utf-8")
        entries = [{"marker_type": "FUNCTION", "va": 0x401000, "name": "f", "filepath": "f.c"}]
        self._patch_mcp(monkeypatch, "int f(int a)")  # Ghidra says 1 param, local has 2
        n = pull_params(entries, self._cfg(tmp_path), "http://mcp", "/prog", dry_run=False)
        assert n == 0  # never guess on arity mismatch
        assert src.read_text(encoding="utf-8") == "int f(int, int) { return 0; }\n"


# ---------------------------------------------------------------------------
# Property-based: apply_param_names preserves arity and never overwrites.
# ---------------------------------------------------------------------------


@st.composite
def simple_param(draw) -> str:
    """A simple named-or-unnamed C parameter (no function pointers)."""
    types = draw(st.sampled_from(["int", "char", "char *", "int *", "unsigned int", "short"]))
    named = draw(st.booleans())
    if not named:
        return types
    name = draw(st.from_regex(r"[a-z][a-z0-9_]{0,6}", fullmatch=True))
    return f"{types} {name}"


@given(st.lists(simple_param(), min_size=0, max_size=6), st.data())
@settings(max_examples=100, deadline=None)
def test_apply_param_names_properties(params: list[str], data: Any) -> None:
    """For any simple param list: arity preserved, named params untouched,
    unnamed params filled, and the result still parses."""
    from rebrew.ghidra.params import apply_param_names, param_names_from_proto

    names = [f"p{i}" for i in range(len(params))]
    signature = "int f(" + ", ".join(params) + ")"
    source = signature + " { return 0; }"

    out = apply_param_names(source, "f", names)
    if out is None:
        # All-named or empty — nothing to do, or arity 0.
        return
    # Arity preserved: the rewritten signature still has the same count.
    local = param_names_from_proto(out.split("{")[0])
    assert local is not None
    assert len(local) == len(params)
    # Every param that was already named keeps its name.
    for i, part in enumerate(params):
        tokens = part.split()
        if tokens[-1].lstrip("*") not in _TYPE_KEYWORDS and tokens[-1].lstrip("*") != "":
            assert local[i] == tokens[-1].lstrip("*"), f"{part} was overwritten -> {local}"
    # Every unnamed param got a name.
    for i, part in enumerate(params):
        tokens = part.split()
        last = tokens[-1].lstrip("*")
        if last in _TYPE_KEYWORDS or last == "":
            assert local[i] == names[i], f"{part} not filled -> {local[i]!r}"
