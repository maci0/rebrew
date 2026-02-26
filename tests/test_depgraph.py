"""Tests for rebrew.depgraph graph building and rendering."""

from rebrew.depgraph import (
    _extract_callees,
    _focus_graph,
    build_graph,
    render_dot,
    render_mermaid,
    render_summary,
)


class TestExtractCallees:
    def test_basic_extern(self, tmp_path) -> None:
        c = tmp_path / "test.c"
        c.write_text(
            "// FUNCTION: SERVER 0x10001000\n"
            "extern int __cdecl FooBar(int x);\n"
            "extern void __cdecl BazQux(void);\n",
            encoding="utf-8",
        )
        callees = _extract_callees(c)
        assert "FooBar" in callees
        assert "BazQux" in callees

    def test_filters_stdlib(self, tmp_path) -> None:
        c = tmp_path / "test.c"
        c.write_text(
            "extern void* __cdecl malloc(unsigned int);\n"
            "extern int __cdecl strlen(const char *);\n"
            "extern int __cdecl MyFunc(int);\n",
            encoding="utf-8",
        )
        callees = _extract_callees(c)
        assert "malloc" not in callees
        assert "strlen" not in callees
        assert "MyFunc" in callees

    def test_stdcall(self, tmp_path) -> None:
        c = tmp_path / "test.c"
        c.write_text("extern int __stdcall WSASend(int, void*, int);\n", encoding="utf-8")
        callees = _extract_callees(c)
        assert "WSASend" in callees

    def test_no_extern(self, tmp_path) -> None:
        c = tmp_path / "test.c"
        c.write_text("int main() { return 0; }\n", encoding="utf-8")
        assert _extract_callees(c) == []


class TestBuildGraph:
    def _make_c_file(self, d, name, va, status, origin, externs=None) -> None:
        """Helper to create a minimal .c file with annotations."""
        lines = [
            f"// FUNCTION: SERVER 0x{va:08x}",
            f"// STATUS: {status}",
            f"// ORIGIN: {origin}",
            "// SIZE: 100",
            "// CFLAGS: /O2 /Gd",
            f"// SYMBOL: _{name}",
            "",
        ]
        for ext in externs or []:
            lines.append(f"extern int __cdecl {ext}(void);")
        lines.append(f"int __cdecl {name}(void) {{ return 0; }}")
        (d / f"{name}.c").write_text("\n".join(lines), encoding="utf-8")

    def test_basic_graph(self, tmp_path) -> None:
        self._make_c_file(tmp_path, "FuncA", 0x10001000, "RELOC", "GAME", ["FuncB"])
        self._make_c_file(tmp_path, "FuncB", 0x10002000, "STUB", "GAME")
        nodes, edges = build_graph(tmp_path)
        assert "FuncA" in nodes
        assert "FuncB" in nodes
        assert ("FuncA", "FuncB") in edges

    def test_unknown_callee(self, tmp_path) -> None:
        self._make_c_file(tmp_path, "FuncA", 0x10001000, "RELOC", "GAME", ["UnknownFunc"])
        nodes, edges = build_graph(tmp_path)
        assert "UnknownFunc" in nodes
        assert nodes["UnknownFunc"]["status"] == "UNKNOWN"
        assert ("FuncA", "UnknownFunc") in edges

    def test_origin_filter(self, tmp_path) -> None:
        self._make_c_file(tmp_path, "GameFunc", 0x10001000, "RELOC", "GAME")
        self._make_c_file(tmp_path, "CrtFunc", 0x1001E000, "RELOC", "MSVCRT")
        nodes, _ = build_graph(tmp_path, origin_filter="GAME")
        assert "GameFunc" in nodes
        assert "CrtFunc" not in nodes

    def test_no_self_edges(self, tmp_path) -> None:
        self._make_c_file(tmp_path, "FuncA", 0x10001000, "RELOC", "GAME", ["FuncA"])
        _, edges = build_graph(tmp_path)
        assert ("FuncA", "FuncA") not in edges

    def test_multi_function_file(self, tmp_path) -> None:
        """build_graph should capture ALL annotations from multi-function files.

        Regression test: previously used parse_c_file (single) instead of
        parse_c_file_multi, so only the first annotation was processed.
        """
        # Write a single .c file containing two function annotations
        multi_content = "\n".join(
            [
                "// FUNCTION: SERVER 0x10001000",
                "// STATUS: RELOC",
                "// ORIGIN: GAME",
                "// SIZE: 100",
                "// CFLAGS: /O2 /Gd",
                "// SYMBOL: _FirstFunc",
                "",
                "int __cdecl FirstFunc(void) { return 0; }",
                "",
                "// FUNCTION: SERVER 0x10002000",
                "// STATUS: STUB",
                "// ORIGIN: GAME",
                "// SIZE: 200",
                "// CFLAGS: /O2 /Gd",
                "// SYMBOL: _SecondFunc",
                "",
                "int __cdecl SecondFunc(void) { return 0; }",
            ]
        )
        (tmp_path / "multi.c").write_text(multi_content, encoding="utf-8")

        nodes, _ = build_graph(tmp_path)
        assert "FirstFunc" in nodes, "First annotation in multi-function file should be captured"
        assert "SecondFunc" in nodes, "Second annotation in multi-function file should be captured"
        assert nodes["FirstFunc"]["status"] == "RELOC"
        assert nodes["SecondFunc"]["status"] == "STUB"


class TestFocusGraph:
    def test_focus(self) -> None:
        nodes = {
            "A": {"status": "RELOC", "origin": "GAME", "va": 1, "file": "a.c"},
            "B": {"status": "STUB", "origin": "GAME", "va": 2, "file": "b.c"},
            "C": {"status": "EXACT", "origin": "GAME", "va": 3, "file": "c.c"},
        }
        edges = [("A", "B"), ("B", "C")]
        # Focus on B, depth 1: should include A and C
        fn, fe = _focus_graph(nodes, edges, "B", depth=1)
        assert "A" in fn
        assert "B" in fn
        assert "C" in fn

    def test_focus_depth_0(self) -> None:
        nodes = {
            "A": {"status": "RELOC", "origin": "GAME", "va": 1, "file": "a.c"},
            "B": {"status": "STUB", "origin": "GAME", "va": 2, "file": "b.c"},
        }
        edges = [("A", "B")]
        fn, fe = _focus_graph(nodes, edges, "A", depth=0)
        assert "A" in fn
        assert "B" not in fn

    def test_focus_not_found(self) -> None:
        nodes = {"A": {"status": "RELOC", "origin": "", "va": 1, "file": ""}}
        fn, fe = _focus_graph(nodes, [], "NONEXISTENT")
        assert fn == {}


class TestRenderers:
    def _sample(self) -> tuple[dict[str, dict[str, str | int]], list[tuple[str, str]]]:
        nodes = {
            "FuncA": {"status": "RELOC", "origin": "GAME", "va": 1, "file": "a.c"},
            "FuncB": {"status": "STUB", "origin": "GAME", "va": 2, "file": "b.c"},
            "Unknown": {"status": "UNKNOWN", "origin": "", "va": 0, "file": ""},
        }
        edges = [("FuncA", "FuncB"), ("FuncA", "Unknown")]
        return nodes, edges

    def test_mermaid_output(self) -> None:
        nodes, edges = self._sample()
        result = render_mermaid(nodes, edges)
        assert "graph LR" in result
        assert "FuncA" in result
        assert "FuncB" in result
        # Verify edge structure
        assert "FuncA --> FuncB" in result or "FuncA -->" in result
        assert "classDef exact" in result

    def test_dot_output(self) -> None:
        nodes, edges = self._sample()
        result = render_dot(nodes, edges)
        assert "digraph G" in result
        assert "FuncA" in result
        assert "->" in result

    def test_summary_output(self) -> None:
        nodes, edges = self._sample()
        result = render_summary(nodes, edges)
        assert "Nodes:" in result
        assert "Edges:" in result
        assert "RELOC" in result
        assert "STUB" in result
        # Verify actual counts (3 nodes, 2 edges in sample)
        assert "3" in result
        assert "2" in result
