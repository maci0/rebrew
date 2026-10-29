"""Tests for tools/bench_perf10_analysis.py and the depgraph edge list it times."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from source_util import write_source

from rebrew.depgraph import build_graph
from tools import bench_perf10_analysis as bench


def _once(fn: Any, *, cache_state: str, repeat: int = 0) -> dict[str, Any]:
    """Stand-in for ``measure`` that runs the workload once without timing."""
    fn()
    return {"cache_state": cache_state}


class TestBenchmarkInputs:
    def test_dep_tree_is_deterministic_and_nonempty(self, tmp_path: Path) -> None:
        import random

        first, second = tmp_path / "a", tmp_path / "b"
        first.mkdir()
        second.mkdir()
        bench._make_dep_tree(first, random.Random(bench.SEED))
        bench._make_dep_tree(second, random.Random(bench.SEED))
        names = sorted(p.name for p in first.iterdir())
        assert len(names) == bench.DEP_FILES
        assert all((first / n).read_bytes() == (second / n).read_bytes() for n in names)
        assert "ADDRESS: SERVER" in (first / names[0]).read_text(encoding="utf-8")

    def test_decomps_are_deterministic(self) -> None:
        import random

        assert bench._make_decomps(random.Random(7)) == bench._make_decomps(random.Random(7))
        assert len(bench._make_decomps(random.Random(7))) == bench.DECOMP_FUNCS

    def test_workloads_hit_expected_results(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(bench, "measure", _once)
        dep = bench.bench_depgraph_build()
        assert (dep["dimensions"]["nodes"], dep["dimensions"]["edges"]) == bench.EXPECTED[
            "depgraph_build"
        ]
        st = bench.bench_struct_extract_recover()
        dims = st["dimensions"]
        assert (
            dims["extracted_structs"],
            dims["named_bases"],
            dims["anonymous_vars"],
            dims["synthesized"],
        ) == bench.EXPECTED["struct_extract_recover"]

    def test_json_document(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setattr(bench, "measure", _once)
        monkeypatch.setattr("sys.argv", ["bench_perf10_analysis.py", "--json"])
        bench.main()
        doc = json.loads(capsys.readouterr().out)
        assert set(doc["workloads"]) == {"depgraph_build", "struct_extract_recover"}
        assert doc["repeat"] >= 7


class TestBuildGraphEdges:
    def _cfg(self, d: Path) -> SimpleNamespace:
        return SimpleNamespace(metadata_dir=d, module=None, source_ext=".c", shared_dir=None)

    def test_edges_follow_each_function_body_and_keep_duplicates(self, tmp_path: Path) -> None:
        write_source(
            tmp_path / "merged.c",
            "extern int __cdecl Alpha(void);\n"
            "extern int __cdecl Beta(void);\n"
            "extern int __cdecl Gamma(void);\n"
            "extern int __cdecl Alpha(void);\n"
            "/* ADDRESS: SERVER 0x10001000 */\n"
            "int __cdecl First(void) { return Alpha() + Beta(); }\n"
            "/* ADDRESS: SERVER 0x10002000 */\n"
            "int __cdecl Second(void) { return Gamma() + memcpy(0, 0, 0); }\n"
            "extern void *__cdecl memcpy(void *, const void *, unsigned);\n",
            metadata_fields={
                "SERVER.0x10001000": {"status": "RELOC"},
                "SERVER.0x10002000": {"status": "STUB"},
            },
        )
        _, edges, _ = build_graph(tmp_path, cfg=self._cfg(tmp_path))
        first, second = "va:0x10001000", "va:0x10002000"
        assert edges == [
            (first, "Alpha"),
            (first, "Beta"),
            (first, "Alpha"),
            (second, "Gamma"),
        ]


_ROLE_SOURCES = [
    # Names shared between file scope and function bodies, with shadowing.
    "extern int shared, first, second;\n"
    "int *p = &shared;\n"
    "int f(int second) { return first + second; }\n"
    "int g(void) { int first = 1; { int shared = 2; shared++; } return first + second; }\n",
    # Conditional branches holding both functions and file-scope initializers.
    "extern int a, b, c, d;\n"
    "#ifdef X\n"
    "int *pa = &a;\n"
    "int f(void) { return b; }\n"
    "#else\n"
    "int *pc = &c;\n"
    "int f(void) { return d + a; }\n"
    "#endif\n"
    "int g(void) { return c; }\n",
    # No functions, and a function-only file.
    "extern int only; int *q = &only;\n",
    "extern int h; int f(void) { return h; }\n",
]


class TestGlobalUses:
    @pytest.mark.parametrize("source", _ROLE_SOURCES)
    def test_matches_function_filter_walk_and_leaves_results_unchanged(self, source: str) -> None:
        from rebrew.c_parser import find_variable_roles

        per_function: dict[int, set[str]] = {}
        outside: set[str] = set()
        roles = find_variable_roles(source, function_uses=per_function, global_uses=outside)
        plain_functions: dict[int, set[str]] = {}
        assert roles == find_variable_roles(source, function_uses=plain_functions)
        assert per_function == plain_functions
        assert roles == find_variable_roles(source)
        assert outside == find_variable_roles(source, function_filter=lambda _: False)[2]
        assert outside <= roles[2]

    def test_outside_set_excludes_function_only_names(self) -> None:
        from rebrew.c_parser import find_variable_roles

        outside: set[str] = set()
        find_variable_roles(
            "extern int g, only_in_f;\nint *p = &g;\nint f(void) { return only_in_f; }\n",
            global_uses=outside,
        )
        assert outside == {"g"}
