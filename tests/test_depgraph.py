"""Tests for rebrew.depgraph graph building and rendering."""

from rebrew.data import DispatchEntry, DispatchTable
from rebrew.depgraph import (
    NodeInfo,
    _extract_callees,
    _focus_graph,
    _sanitize_id,
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
        nodes, edges, dispatch_edges = build_graph(tmp_path)
        assert "FuncA" in nodes
        assert "FuncB" in nodes
        assert ("FuncA", "FuncB") in edges
        assert dispatch_edges == []

    def test_unknown_callee(self, tmp_path) -> None:
        self._make_c_file(tmp_path, "FuncA", 0x10001000, "RELOC", "GAME", ["UnknownFunc"])
        nodes, edges, dispatch_edges = build_graph(tmp_path)
        assert "UnknownFunc" in nodes
        assert nodes["UnknownFunc"]["status"] == "UNKNOWN"
        assert ("FuncA", "UnknownFunc") in edges

    def test_no_self_edges(self, tmp_path) -> None:
        self._make_c_file(tmp_path, "FuncA", 0x10001000, "RELOC", "GAME", ["FuncA"])
        _, edges, _ = build_graph(tmp_path)
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

        nodes, _, _ = build_graph(tmp_path)
        assert "FirstFunc" in nodes, "First annotation in multi-function file should be captured"
        assert "SecondFunc" in nodes, "Second annotation in multi-function file should be captured"
        assert nodes["FirstFunc"]["status"] == "RELOC"
        assert nodes["SecondFunc"]["status"] == "STUB"

    def test_dispatch_tables_add_nodes_and_edges(self, tmp_path) -> None:
        """build_graph folds dispatch table entries into dispatch_edges."""
        self._make_c_file(tmp_path, "FuncA", 0x10001000, "RELOC", "GAME")
        self._make_c_file(tmp_path, "FuncB", 0x10002000, "EXACT", "GAME")

        tbl = DispatchTable(
            va=0x20000000,
            section=".rdata",
            entries=[
                DispatchEntry(target_va=0x10001000, name="_FuncA", status="RELOC"),
                DispatchEntry(target_va=0x10002000, name="_FuncB", status="EXACT"),
                # Unresolved target — becomes a VA-based placeholder node
                DispatchEntry(target_va=0x10003000, name="", status=""),
            ],
        )

        nodes, edges, dispatch_edges = build_graph(tmp_path, dispatch_tables=[tbl])

        dispatch_node = "dispatch_0x20000000"
        assert dispatch_node in nodes
        assert nodes[dispatch_node]["status"] == "DISPATCH"
        assert nodes[dispatch_node]["va"] == 0x20000000

        # dispatch_edges connect the virtual node to every entry target
        dispatch_targets = {b for a, b in dispatch_edges if a == dispatch_node}
        assert "FuncA" in dispatch_targets
        assert "FuncB" in dispatch_targets
        # Unresolved entry resolves to VA-based placeholder
        assert "fn_0x10003000" in dispatch_targets

    def test_no_dispatch_when_tables_none(self, tmp_path) -> None:
        """dispatch_tables=None produces empty dispatch_edges (default behaviour)."""
        self._make_c_file(tmp_path, "FuncA", 0x10001000, "EXACT", "GAME")
        _, _, dispatch_edges = build_graph(tmp_path, dispatch_tables=None)
        assert dispatch_edges == []

    def test_multiple_dispatch_tables(self, tmp_path) -> None:
        """Multiple dispatch tables each get their own virtual node."""
        self._make_c_file(tmp_path, "FuncX", 0x10001000, "EXACT", "GAME")

        tbl1 = DispatchTable(
            va=0x20000000,
            section=".rdata",
            entries=[
                DispatchEntry(target_va=0x10001000, name="_FuncX", status="EXACT"),
                DispatchEntry(target_va=0x10001000, name="_FuncX", status="EXACT"),
                DispatchEntry(target_va=0x10001000, name="_FuncX", status="EXACT"),
            ],
        )
        tbl2 = DispatchTable(
            va=0x20001000,
            section=".data",
            entries=[
                DispatchEntry(target_va=0x10001000, name="_FuncX", status="EXACT"),
                DispatchEntry(target_va=0x10001000, name="_FuncX", status="EXACT"),
                DispatchEntry(target_va=0x10001000, name="_FuncX", status="EXACT"),
            ],
        )

        nodes, _, dispatch_edges = build_graph(tmp_path, dispatch_tables=[tbl1, tbl2])

        assert "dispatch_0x20000000" in nodes
        assert "dispatch_0x20001000" in nodes
        dispatchers = {a for a, _ in dispatch_edges}
        assert "dispatch_0x20000000" in dispatchers
        assert "dispatch_0x20001000" in dispatchers


def test_sanitize_id_avoids_collisions() -> None:
    assert _sanitize_id("foo-bar") != _sanitize_id("foo bar")


class TestFocusGraph:
    def test_focus(self) -> None:
        nodes: dict[str, NodeInfo] = {
            "A": {"status": "RELOC", "va": 1, "file": "a.c"},
            "B": {"status": "STUB", "va": 2, "file": "b.c"},
            "C": {"status": "EXACT", "va": 3, "file": "c.c"},
        }
        edges = [("A", "B"), ("B", "C")]
        fn, _, _ = _focus_graph(nodes, edges, "B", depth=1)
        assert "A" in fn
        assert "B" in fn
        assert "C" in fn

    def test_focus_depth_0(self) -> None:
        nodes: dict[str, NodeInfo] = {
            "A": {"status": "RELOC", "va": 1, "file": "a.c"},
            "B": {"status": "STUB", "va": 2, "file": "b.c"},
        }
        edges = [("A", "B")]
        fn, _, _ = _focus_graph(nodes, edges, "A", depth=0)
        assert "A" in fn
        assert "B" not in fn

    def test_focus_not_found(self) -> None:
        nodes: dict[str, NodeInfo] = {"A": {"status": "RELOC", "va": 1, "file": ""}}
        fn, _, _ = _focus_graph(nodes, [], "NONEXISTENT")
        assert fn == {}

    def test_focus_includes_dispatch_neighbours(self) -> None:
        """_focus_graph BFS traverses dispatch edges when finding neighbours.

        Graph:
          dispatch_0x20000000 --dispatch--> FuncA  (depth 1 from FuncA)
          dispatch_0x20000000 --dispatch--> FuncB  (depth 2 from FuncA)

        At depth=1 the focus BFS reaches the dispatch node (1 hop).
        At depth=2 it additionally reaches FuncB (via dispatch node -> FuncB).
        """
        nodes: dict[str, NodeInfo] = {
            "FuncA": {"status": "RELOC", "va": 1, "file": "a.c"},
            "dispatch_0x20000000": {"status": "DISPATCH", "va": 0x20000000, "file": ""},
            "FuncB": {"status": "EXACT", "va": 2, "file": "b.c"},
        }
        edges: list[tuple[str, str]] = []
        dispatch_edges = [("dispatch_0x20000000", "FuncA"), ("dispatch_0x20000000", "FuncB")]

        # depth=1: only the dispatch node is reachable (1 hop)
        fn1, _, _ = _focus_graph(nodes, edges, "FuncA", depth=1, dispatch_edges=dispatch_edges)
        assert "FuncA" in fn1
        assert "dispatch_0x20000000" in fn1
        assert "FuncB" not in fn1  # 2 hops away — beyond depth=1

        # depth=2: dispatch node and FuncB both reachable
        fn2, _, fde2 = _focus_graph(nodes, edges, "FuncA", depth=2, dispatch_edges=dispatch_edges)
        assert "FuncA" in fn2
        assert "dispatch_0x20000000" in fn2
        assert "FuncB" in fn2
        # Dispatch edge to FuncB should be preserved in the filtered set
        assert ("dispatch_0x20000000", "FuncB") in fde2


class TestRenderers:
    def _sample(self) -> tuple[dict[str, NodeInfo], list[tuple[str, str]]]:
        nodes: dict[str, NodeInfo] = {
            "FuncA": {"status": "RELOC", "va": 1, "file": "a.c"},
            "FuncB": {"status": "STUB", "va": 2, "file": "b.c"},
            "Unknown": {"status": "UNKNOWN", "va": 0, "file": ""},
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
        assert "n_FuncA_" in result
        assert "n_FuncB_" in result
        assert "classDef exact" in result

    def test_mermaid_dispatch_style(self) -> None:
        """Dispatch edges render as dashed arrows (..>) in mermaid output."""
        nodes: dict[str, NodeInfo] = {
            "dispatch_0x20000000": {"status": "DISPATCH", "va": 0x20000000, "file": ""},
            "FuncA": {"status": "EXACT", "va": 1, "file": "a.c"},
        }
        edges: list[tuple[str, str]] = []
        dispatch_edges = [("dispatch_0x20000000", "FuncA")]
        result = render_mermaid(nodes, edges, dispatch_edges)
        assert "..>" in result
        assert "classDef dispatch" in result

    def test_mermaid_no_dispatch_edges_when_empty(self) -> None:
        """No dashed arrows appear when dispatch_edges is empty or None."""
        nodes, edges = self._sample()
        for de in (None, []):
            result = render_mermaid(nodes, edges, de)
            assert "..>" not in result

    def test_dot_output(self) -> None:
        nodes, edges = self._sample()
        result = render_dot(nodes, edges)
        assert "digraph G" in result
        assert "FuncA" in result
        assert "->" in result

    def test_dot_matching_reloc_color(self) -> None:
        nodes: dict[str, NodeInfo] = {"FuncM": {"status": "NEAR_MATCHING", "va": 1, "file": "m.c"}}
        result = render_dot(nodes, [])
        assert "#f39c12" in result

    def test_dot_dispatch_style(self) -> None:
        """Dispatch edges render with style=dashed in DOT output."""
        nodes: dict[str, NodeInfo] = {
            "dispatch_0x20000000": {"status": "DISPATCH", "va": 0x20000000, "file": ""},
            "FuncA": {"status": "EXACT", "va": 1, "file": "a.c"},
        }
        edges: list[tuple[str, str]] = []
        dispatch_edges = [("dispatch_0x20000000", "FuncA")]
        result = render_dot(nodes, edges, dispatch_edges)
        assert "style=dashed" in result

    def test_dot_dispatch_node_color(self) -> None:
        """Dispatch nodes get a distinct fill color (#9b59b6)."""
        nodes: dict[str, NodeInfo] = {
            "dispatch_0x20000000": {"status": "DISPATCH", "va": 0x20000000, "file": ""},
        }
        result = render_dot(nodes, [])
        assert "#9b59b6" in result

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

    def test_summary_with_dispatch(self) -> None:
        """Summary reports dispatch node and edge counts when present."""
        nodes: dict[str, NodeInfo] = {
            "FuncA": {"status": "EXACT", "va": 1, "file": "a.c"},
            "dispatch_0x20000000": {"status": "DISPATCH", "va": 0x20000000, "file": ""},
        }
        edges: list[tuple[str, str]] = []
        dispatch_edges = [("dispatch_0x20000000", "FuncA")]
        result = render_summary(nodes, edges, dispatch_edges)
        assert "dispatch" in result
        assert "DISPATCH" in result
