"""Unit tests for tools/check_layering.py."""

import ast
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import check_layering as cl  # noqa: E402


def _from_import(source: str) -> ast.ImportFrom:
    node = ast.parse(source).body[0]
    assert isinstance(node, ast.ImportFrom)
    return node


def _tree(source: str) -> ast.Module:
    return ast.parse(source)


class TestRebrewTargets:
    def test_absolute_module_import(self) -> None:
        node = _from_import("from rebrew.pe_image import PeImport")
        assert cl._rebrew_targets(
            "rebrew.verify", False, node, {"rebrew.pe_image", "rebrew.verify"}
        ) == {"rebrew.pe_image"}

    def test_dotted_absolute_import_resolves_to_package(self) -> None:
        node = _from_import("from rebrew.catalog.loaders import cached_function_list")
        assert cl._rebrew_targets(
            "rebrew.verify", False, node, {"rebrew.catalog", "rebrew.verify"}
        ) == {"rebrew.catalog"}

    def test_relative_import_of_sibling(self) -> None:
        node = _from_import("from .core import Score")
        known = {"rebrew.matcher.core", "rebrew.matcher.compiler"}
        assert cl._rebrew_targets("rebrew.matcher.compiler", False, node, known) == {
            "rebrew.matcher.core"
        }

    def test_relative_import_inside_package_keeps_own_package(self) -> None:
        node = _from_import("from .grid import covered_bytes")
        known = {"rebrew.catalog.grid", "rebrew.catalog"}
        assert cl._rebrew_targets("rebrew.catalog", True, node, known) == {"rebrew.catalog.grid"}

    def test_bare_relative_import(self) -> None:
        node = _from_import("from . import serial")
        known = {"rebrew.binsync", "rebrew.binsync.state"}
        assert cl._rebrew_targets("rebrew.binsync.state", False, node, known) == {"rebrew.binsync"}

    def test_third_party_import_ignored(self) -> None:
        node = _from_import("from pathlib import Path")
        assert cl._rebrew_targets("rebrew.utils", False, node, {"rebrew.utils"}) == set()


class TestModuleScopeImports:
    def test_function_import_skipped(self) -> None:
        tree = _tree(
            "from rebrew.cli import error_exit\ndef f():\n    from rebrew.main import app\n"
        )
        assert len(list(cl._module_scope_imports(tree))) == 1

    def test_type_checking_guard_skipped(self) -> None:
        tree = _tree(
            "from rebrew.cli import error_exit\nif TYPE_CHECKING:\n    from rebrew.main import app\n"
        )
        assert len(list(cl._module_scope_imports(tree))) == 1

    def test_try_block_included(self) -> None:
        tree = _tree("try:\n    from rebrew.main import app\nexcept ImportError:\n    app = None\n")
        assert len(list(cl._module_scope_imports(tree))) == 1


class TestCheckLayering:
    def _write(self, root: Path, rel: str, content: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_clean_package_passes(self, tmp_path: Path) -> None:
        pkg = tmp_path / "src" / "rebrew"
        self._write(pkg, "utils.py", "import os\n")
        self._write(pkg, "cli.py", "from rebrew.utils import console\n")
        self._write(pkg, "verify.py", "from rebrew.cli import error_exit\n")
        self._write(pkg, "builtins.py", "BUILTIN_COMPONENTS = []\n")
        self._write(pkg, "main.py", "from rebrew.builtins import BUILTIN_COMPONENTS\n")
        self._write(pkg, "init.py", "def register():\n    from rebrew.main import app\n")
        assert cl.check_layering(str(pkg)) == []

    def test_leaf_module_import_is_reported(self, tmp_path: Path) -> None:
        pkg = tmp_path / "src" / "rebrew"
        self._write(pkg, "config.py", "class ProjectConfig:\n    pass\n")
        self._write(pkg, "utils.py", "from rebrew.config import ProjectConfig\n")
        violations = cl.check_layering(str(pkg))
        assert [(v.module, v.rule, v.target) for v in violations] == [
            ("rebrew.utils", "leaf module", "rebrew.config")
        ]

    def test_composition_import_is_reported(self, tmp_path: Path) -> None:
        pkg = tmp_path / "src" / "rebrew"
        self._write(pkg, "dashboard.py", "def render() -> None:\n    pass\n")
        self._write(pkg, "verify.py", "from rebrew.dashboard import render\n")
        violations = cl.check_layering(str(pkg))
        assert [(v.module, v.rule, v.target) for v in violations] == [
            ("rebrew.verify", "composition-layer import", "rebrew.dashboard")
        ]

    def test_composition_layer_may_import_itself(self, tmp_path: Path) -> None:
        pkg = tmp_path / "src" / "rebrew"
        self._write(pkg, "dashboard.py", "def render() -> None:\n    pass\n")
        self._write(pkg, "plugin.py", "from rebrew.dashboard import render\n")
        assert cl.check_layering(str(pkg)) == []

    def test_relative_import_resolves_inside_package(self, tmp_path: Path) -> None:
        pkg = tmp_path / "src" / "rebrew"
        self._write(pkg, "commands/__init__.py", "from .cli import command\n")
        self._write(pkg, "dashboard.py", "def render() -> None:\n    pass\n")
        self._write(pkg, "commands/cli.py", "from rebrew.dashboard import render\n")
        violations = cl.check_layering(str(pkg))
        assert [(v.module, v.target) for v in violations] == [
            ("rebrew.commands.cli", "rebrew.dashboard")
        ]
