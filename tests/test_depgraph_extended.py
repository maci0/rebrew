"""Tests for rebrew depgraph — build_graph branches, summary edges, CLI main."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.depgraph import build_graph, render_summary


def _cfg(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    src = tmp_path / "src" / "SERVER"
    src.mkdir(parents=True, exist_ok=True)
    defaults: dict = {
        "root": tmp_path,
        "target_name": "SERVER",
        "target_binary": tmp_path / "fake.dll",
        "reversed_dir": src,
        "metadata_dir": tmp_path,
        "marker": "SERVER",
        "source_ext": ".c",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestBuildGraphBranches:
    def test_unreadable_file_skipped(self, tmp_path: Path) -> None:
        """A *.c entry that is actually a directory → read raises OSError → skip."""
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "dir.c").mkdir()  # directory matching *.c glob
        nodes, edges, d_edges = build_graph(cfg.reversed_dir, cfg)
        assert nodes == {}
        assert edges == []
        assert d_edges == []

    def test_global_marker_skipped(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "g.c").write_text(
            "// GLOBAL: SERVER 0x1000\n// SYMBOL: g_x\nextern int g_x;\n",
            encoding="utf-8",
        )
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x2000\n// SYMBOL: _my_func\n"
            "extern int g_x;\nint my_func(void) { return g_x; }\n",
            encoding="utf-8",
        )
        nodes, edges, _ = build_graph(cfg.reversed_dir, cfg)
        assert "g_x" not in nodes  # GLOBAL markers are not graph nodes
        assert "my_func" in nodes

    def test_dispatch_entry_name_fallback(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x2000\n// SYMBOL: _my_func\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        tbl = SimpleNamespace(
            va=0x4000,
            entries=[SimpleNamespace(target_va=0x9999, name="_resolved_name", status="UNKNOWN")],
        )
        nodes, _edges, d_edges = build_graph(cfg.reversed_dir, cfg, dispatch_tables=[tbl])
        assert "dispatch_0x00004000" in nodes
        # Unknown target VA with a resolved name → fallback to the name.
        assert ("dispatch_0x00004000", "resolved_name") in d_edges
        assert "resolved_name" in nodes

    def test_dispatch_target_placeholder(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        tbl = SimpleNamespace(
            va=0x4000,
            entries=[SimpleNamespace(target_va=0x9999, name="", status="STUB")],
        )
        nodes, _edges, d_edges = build_graph(cfg.reversed_dir, cfg, dispatch_tables=[tbl])
        # No name → fn_0x<VA> placeholder node with the entry's status.
        assert ("dispatch_0x00004000", "fn_0x00009999") in d_edges
        assert nodes["fn_0x00009999"]["status"] == "STUB"


class TestRenderSummaryEdges:
    def test_leaves_and_blockers(self) -> None:
        nodes = {
            "a": {"status": "EXACT", "va": 0x1, "file": "a.c"},
            "b": {"status": "STUB", "va": 0x2, "file": "b.c"},
            "u1": {"status": "UNKNOWN", "va": 0, "file": ""},
            "u2": {"status": "UNKNOWN", "va": 0, "file": ""},
            "d": {"status": "DISPATCH", "va": 0x4000, "file": ""},
        }
        edges = [("a", "u1"), ("a", "u2")]
        out = render_summary(nodes, edges, [("d", "b")])
        assert "Leaf functions" in out
        assert "b" in out  # b is called (by d) but calls nothing → leaf
        # Top blockers: u1 called by a only.
        assert "u1: called by 1 functions" in out
        assert "EXACT: 1" in out
        assert "DISPATCH: 1" in out

    def test_no_leaves_or_blockers(self) -> None:
        nodes = {"a": {"status": "EXACT", "va": 0x1, "file": "a.c"}}
        out = render_summary(nodes, [("a", "a")], None)
        assert "Nodes: 1" in out
        assert "Leaf functions" not in out
        assert "Top unreversed blockers" not in out


class TestDepgraphCli:
    def _cfg_and_patch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:

        cfg = _cfg(tmp_path)
        monkeypatch.setattr("rebrew.depgraph.require_config", lambda **kw: cfg)
        return cfg

    def test_summary_format(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.depgraph import app

        cfg = self._cfg_and_patch(tmp_path, monkeypatch)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x2000\n// SYMBOL: _my_func\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        result = CliRunner().invoke(app, ["--format", "summary"])
        assert result.exit_code == 0
        assert "Nodes:" in result.stdout

    def test_json_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.depgraph import app

        cfg = self._cfg_and_patch(tmp_path, monkeypatch)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x2000\n// SYMBOL: _my_func\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["total_nodes"] == 1
        assert "my_func" in data["nodes"]

    def test_output_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.depgraph import app

        cfg = self._cfg_and_patch(tmp_path, monkeypatch)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x2000\n// SYMBOL: _my_func\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        out = tmp_path / "graph.md"
        result = CliRunner().invoke(app, ["-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert "graph LR" in out.read_text(encoding="utf-8")

    def test_no_functions_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.depgraph import app

        self._cfg_and_patch(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, [])
        assert result.exit_code != 0
        assert "No functions found" in result.output

    def test_focus_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.depgraph import app

        cfg = self._cfg_and_patch(tmp_path, monkeypatch)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x2000\n// SYMBOL: _my_func\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        result = CliRunner().invoke(app, ["--focus", "nonexistent"])
        assert result.exit_code != 0
        assert "No function matching" in result.output

    def test_unknown_format_error(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.depgraph import app

        cfg = self._cfg_and_patch(tmp_path, monkeypatch)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x2000\n// SYMBOL: _my_func\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        result = CliRunner().invoke(app, ["--format", "svg"])
        assert result.exit_code != 0
        assert "Unknown format" in result.output

    def test_include_dispatch_missing_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.depgraph import app

        cfg = self._cfg_and_patch(tmp_path, monkeypatch)
        cfg.target_binary = tmp_path / "missing.dll"
        result = CliRunner().invoke(app, ["--include-dispatch"])
        assert result.exit_code != 0
        assert "requires a target binary" in result.output

    def test_cu_map_dispatch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.depgraph import app

        self._cfg_and_patch(tmp_path, monkeypatch)
        calls = {"n": 0}

        def _cu_map(json_output=False, target=None):
            calls["n"] += 1

        monkeypatch.setattr("rebrew.cu_map.main", _cu_map)
        result = CliRunner().invoke(app, ["--cu-map"])
        assert result.exit_code == 0
        assert calls["n"] == 1


class TestDepgraphCliMore:
    def test_dot_format_cli(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.depgraph import app

        cfg = _cfg(tmp_path)
        monkeypatch.setattr("rebrew.depgraph.require_config", lambda **kw: cfg)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x2000\n// SYMBOL: _my_func\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        result = CliRunner().invoke(app, ["--format", "dot"])
        assert result.exit_code == 0
        assert "digraph G" in result.stdout

    def test_focus_partial_match(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.depgraph import app

        cfg = _cfg(tmp_path)
        monkeypatch.setattr("rebrew.depgraph.require_config", lambda **kw: cfg)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x2000\n// SYMBOL: _parse_message\nint parse_message(void) { return 0; }\n",
            encoding="utf-8",
        )
        result = CliRunner().invoke(app, ["--focus", "message"])
        assert result.exit_code == 0
        assert "parse_message" in result.stdout


class TestFocusByVa:
    def test_focus_matches_hex_va(self) -> None:
        from rebrew.depgraph import _focus_graph

        nodes = {
            "func_a": {"status": "EXACT", "va": 0x1000, "file": "a.c"},
            "func_b": {"status": "RELOC", "va": 0x2000, "file": "b.c"},
            "func_c": {"status": "STUB", "va": 0x3000, "file": "c.c"},
        }
        edges = [("func_a", "func_b"), ("func_b", "func_c")]
        filtered, f_edges, _ = _focus_graph(nodes, edges, "0x2000", depth=1)
        assert set(filtered) == {"func_a", "func_b", "func_c"}  # b + neighbours
        assert "func_b" in filtered
        assert f_edges == [("func_a", "func_b"), ("func_b", "func_c")]

    def test_focus_va_without_match_returns_empty(self) -> None:
        from rebrew.depgraph import _focus_graph

        nodes = {"func_a": {"status": "EXACT", "va": 0x1000, "file": "a.c"}}
        filtered, f_edges, _ = _focus_graph(nodes, [], "0x9999", depth=1)
        assert filtered == {} and f_edges == []

    def test_focus_va_beats_placeholder_partial_name(self) -> None:
        from rebrew.depgraph import _focus_graph

        # A dispatch-placeholder node literally named "fn_0x1000_..." must
        # not shadow the real function at VA 0x1000 for --focus 0x1000.
        nodes = {
            "func_a": {"status": "EXACT", "va": 0x1000, "file": "a.c"},
            "fn_0x1000_placeholder": {"status": "STUB", "va": 0, "file": "x.c"},
        }
        edges = [("func_a", "fn_0x1000_placeholder")]
        filtered, f_edges, _ = _focus_graph(nodes, edges, "0x1000", depth=1)
        assert "func_a" in filtered  # the real function at the VA
        assert filtered["func_a"]["va"] == 0x1000
