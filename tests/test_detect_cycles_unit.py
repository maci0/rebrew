"""Unit tests for tools/detect_cycles.py helpers."""

import ast
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import detect_cycles as dc  # noqa: E402


def _parse(src: str) -> list[ast.stmt]:
    return ast.parse(src).body


class TestModuleLevelImports:
    def test_filters_function_imports(self) -> None:
        stmts = _parse(
            "import os\ndef f():\n    import json\n    from rebrew.x import y\nimport sys\n"
        )
        found = dc._module_level_imports(stmts)
        names = []
        for node in found:
            if isinstance(node, ast.Import):
                names.extend(a.name for a in node.names)
            else:
                names.append(node.module)
        assert "os" in names
        assert "sys" in names
        assert "json" not in names  # function-scope import skipped

    def test_skips_type_checking_guard(self) -> None:
        stmts = _parse(
            "from __future__ import annotations\n"
            "if TYPE_CHECKING:\n"
            "    from rebrew.catalog import FunctionEntry\n"
        )
        found = dc._module_level_imports(stmts)
        modules = [n.module for n in found if isinstance(n, ast.ImportFrom) and n.module]
        assert "__future__" in modules
        assert "rebrew.catalog" not in modules  # TYPE_CHECKING guard skipped

    def test_try_imports_included(self) -> None:
        stmts = _parse("try:\n    import angr\nexcept ImportError:\n    angr = None\n")
        found = dc._module_level_imports(stmts)
        assert any(isinstance(n, ast.Import) and n.names[0].name == "angr" for n in found)


class TestGetImports:
    def test_prefix_filtered(self, tmp_path: Path) -> None:
        f = tmp_path / "m.py"
        f.write_text(
            "import os\nimport rebrew.alpha\nfrom rebrew.beta import x\nfrom typing import Any\n",
            encoding="utf-8",
        )
        assert dc._get_imports(str(f), "rebrew") == ["rebrew.alpha", "rebrew.beta"]

    def test_bad_syntax_returns_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text("def broken(:\n", encoding="utf-8")
        assert dc._get_imports(str(f), "rebrew") == []


class TestDetectCycles:
    def _write(self, root: Path, rel: str, content: str) -> None:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def test_detects_cycle(self, tmp_path: Path, monkeypatch) -> None:
        # detect_cycles derives module names assuming root="src/rebrew"
        # relative to the cwd (path[4:-3]).
        monkeypatch.chdir(tmp_path)
        pkg = tmp_path / "src" / "rebrew" / "x"
        self._write(pkg, "a.py", "import rebrew.x.b\n")
        self._write(pkg, "b.py", "import rebrew.x.a\n")
        cycles = dc.detect_cycles("src/rebrew")
        assert any({"rebrew.x.a", "rebrew.x.b"} <= set(c) for c in cycles)

    def test_clean_package_no_cycles(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        pkg = tmp_path / "src" / "rebrew" / "x"
        self._write(pkg, "a.py", "import rebrew.x.b\n")
        self._write(pkg, "b.py", "import os\n")
        assert dc.detect_cycles("src/rebrew") == []
