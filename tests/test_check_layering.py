"""Unit tests for tools/check_layering.py."""

import ast
from pathlib import Path

from tools import check_layering as cl


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


class TestPackageExternals:
    """The allowlist gate: a subpackage may leave only through its AGENTS.md list."""

    def _write(self, root: Path, rel: str, content: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _workspace_pkg(self, tmp_path: Path) -> Path:
        pkg = tmp_path / "src" / "rebrew"
        self._write(pkg, "errors.py", "class RebrewError(Exception):\n    pass\n")
        self._write(pkg, "utils.py", "console = None\n")
        self._write(pkg, "workspace/__init__.py", "from .config import find_root\n")
        return pkg

    def test_declared_external_passes(self, tmp_path: Path) -> None:
        pkg = self._workspace_pkg(tmp_path)
        self._write(pkg, "workspace/config.py", "from rebrew.errors import RebrewError\n")
        assert cl.check_layering(str(pkg)) == []

    def test_undeclared_external_is_reported(self, tmp_path: Path) -> None:
        pkg = self._workspace_pkg(tmp_path)
        self._write(pkg, "workspace/config.py", "from rebrew.utils import console\n")
        violations = cl.check_layering(str(pkg))
        assert [(v.module, v.rule, v.target) for v in violations] == [
            ("rebrew.workspace.config", "undeclared package external", "rebrew.utils")
        ]

    def test_lazy_import_is_checked_too(self, tmp_path: Path) -> None:
        pkg = self._workspace_pkg(tmp_path)
        self._write(
            pkg,
            "workspace/config.py",
            "def find_root() -> None:\n    from rebrew.utils import console\n",
        )
        violations = cl.check_layering(str(pkg))
        assert [(v.module, v.target) for v in violations] == [
            ("rebrew.workspace.config", "rebrew.utils")
        ]

    def test_own_submodule_import_is_allowed(self, tmp_path: Path) -> None:
        pkg = self._workspace_pkg(tmp_path)
        self._write(pkg, "workspace/status.py", "KNOWN_STATUSES: frozenset[str] = frozenset()\n")
        self._write(
            pkg, "workspace/config.py", "from rebrew.workspace.status import KNOWN_STATUSES\n"
        )
        assert cl.check_layering(str(pkg)) == []

    def test_real_tree_matches_the_allowlist(self) -> None:
        assert cl.check_layering("src/rebrew") == []


class TestLibraryDoesNotImportCommand:
    """A module with no Typer app of its own may not import one that has."""

    _COMMAND = (
        "import typer\napp = typer.Typer()\ndef main_entry() -> None:\n    pass\n"
        "def resolve() -> int:\n    return 1\n"
    )
    _LIBRARY = "def resolve() -> int:\n    return 1\n"

    @staticmethod
    def _write(root: Path, rel: str, content: str) -> None:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_library_importing_a_command_is_reported(self, tmp_path: Path) -> None:
        pkg = tmp_path / "src" / "rebrew"
        self._write(pkg, "build_db.py", self._COMMAND)
        self._write(pkg, "coverage_db.py", self._LIBRARY)
        self._write(pkg, "coverage_toml.py", "from rebrew.build_db import resolve\n")
        assert [(v.module, v.rule, v.target) for v in cl.check_layering(str(pkg))] == [
            ("rebrew.coverage_toml", "library imports a command", "rebrew.build_db")
        ]

    def test_library_may_import_a_library(self, tmp_path: Path) -> None:
        pkg = tmp_path / "src" / "rebrew"
        self._write(pkg, "build_db.py", self._COMMAND)
        self._write(pkg, "coverage_db.py", self._LIBRARY)
        self._write(pkg, "coverage_toml.py", "from rebrew.coverage_db import resolve\n")
        assert cl.check_layering(str(pkg)) == []

    def test_a_command_may_import_another_command(self, tmp_path: Path) -> None:
        pkg = tmp_path / "src" / "rebrew"
        self._write(pkg, "build_db.py", self._COMMAND)
        self._write(
            pkg,
            "rebrew_cli.py",
            "import typer\napp = typer.Typer()\nfrom rebrew.build_db import resolve\n"
            "def main_entry() -> None:\n    pass\n",
        )
        assert cl.check_layering(str(pkg)) == []

    def test_lazy_library_import_of_a_command_is_reported(self, tmp_path: Path) -> None:
        pkg = tmp_path / "src" / "rebrew"
        self._write(pkg, "build_db.py", self._COMMAND)
        self._write(
            pkg,
            "match_run.py",
            "def run() -> int:\n    from rebrew.build_db import resolve\n    return resolve()\n",
        )
        assert [(v.rule, v.target) for v in cl.check_layering(str(pkg))] == [
            ("library imports a command", "rebrew.build_db")
        ]

    def test_type_checking_re_export_of_a_command_is_allowed(self, tmp_path: Path) -> None:
        pkg = tmp_path / "src" / "rebrew"
        self._write(pkg, "build_db.py", self._COMMAND)
        self._write(
            pkg,
            "errors.py",
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n    from rebrew.build_db import BuildDbError as BuildDbError\n",
        )
        assert cl.check_layering(str(pkg)) == []

    def test_the_real_tree_has_only_the_two_named_edges(self) -> None:
        tree = {name for name, _, _ in cl._walk_modules("src/rebrew")}
        commands = set()
        for module, path, _ in cl._walk_modules("src/rebrew"):
            if cl._is_command_module(ast.parse(path.read_bytes())):
                commands.add(module)
        for module, target in cl.DEFERRED_LIBRARY_COMMAND_EDGES:
            assert module in tree and target in commands
            assert module not in commands, "a deferred edge's source gained a command"


class TestPackageExternalsStayDocumented:
    """The allowlist is transcribed from each package's AGENTS.md; keep them in step."""

    @staticmethod
    def _externals_paragraph(package: str) -> str:
        agents = Path("src/rebrew") / package / "AGENTS.md"
        text = agents.read_text(encoding="utf-8")
        start = text.index("Externals (the only")
        end = text.index("\n\n", start)
        return text[start:end]

    def test_every_allowed_name_is_documented(self) -> None:
        undocumented: list[str] = []
        for package, allowed in cl.PACKAGE_EXTERNALS.items():
            paragraph = self._externals_paragraph(package)
            undocumented += [
                f"{package}:{name}" for name in sorted(allowed) if f"`{name}`" not in paragraph
            ]
        assert undocumented == []

    def test_every_package_is_covered(self) -> None:
        packages = {p.name for p in Path("src/rebrew").iterdir() if (p / "AGENTS.md").exists()}
        assert packages == set(cl.PACKAGE_EXTERNALS)
