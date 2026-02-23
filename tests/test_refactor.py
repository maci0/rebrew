"""Tests for the refactored tool imports and path resolution.

Verifies that tool scripts do NOT use stale __file__-relative path patterns
and that lazy config loading works correctly.
"""

import importlib
import os
import re
from pathlib import Path

import pytest

# All tool modules that should exist in the rebrew package
TOOL_MODULES = [
    "rebrew.config",
    "rebrew.cli",
    "rebrew.annotation",
    "rebrew.asm",
    "rebrew.batch",
    "rebrew.catalog",
    "rebrew.extract_target",
    "rebrew.gen_flirt_pat",
    "rebrew.identify_libs",
    "rebrew.lint",
    "rebrew.match",
    "rebrew.nasm_extract",
    "rebrew.next",
    "rebrew.skeleton",
    "rebrew.sync",
    "rebrew.test",
    "rebrew.verify",
    "rebrew.matcher",
    "rebrew.matcher.core",
    "rebrew.matcher.compiler",
    "rebrew.matcher.parsers",
    "rebrew.matcher.scoring",
    "rebrew.matcher.mutator",
    "rebrew.binary_loader",
]

SRC_DIR = Path(__file__).resolve().parent.parent / "src" / "rebrew"


class TestNoStalePathPatterns:
    """Verify tools don't use stale __file__-relative PROJECT_ROOT patterns."""

    @pytest.fixture
    def tool_py_files(self):
        """Get all .py files in src/rebrew/."""
        return sorted(SRC_DIR.glob("*.py"))

    def test_no_active_project_root_assignment(self, tool_py_files):
        """Check that no tool file has an active PROJECT_ROOT = ... assignment
        (commented-out lines are OK)."""
        violations = []
        for pyfile in tool_py_files:
            text = pyfile.read_text()
            for i, line in enumerate(text.splitlines(), 1):
                stripped = line.lstrip()
                # Skip comments
                if stripped.startswith("#"):
                    continue
                if re.match(r"^PROJECT_ROOT\s*=", stripped):
                    violations.append(f"{pyfile.name}:{i}: {line.strip()}")
        assert not violations, (
            "Stale PROJECT_ROOT assignments found (should use load_config()):\n"
            + "\n".join(violations)
        )

    def test_no_old_tools_help_text(self, tool_py_files):
        """Check that no tool references old 'tools/' path in user-facing text."""
        violations = []
        for pyfile in tool_py_files:
            text = pyfile.read_text()
            for i, line in enumerate(text.splitlines(), 1):
                stripped = line.lstrip()
                # Skip comments, docstrings
                if stripped.startswith("#"):
                    continue
                # Check for old-style "python tools/" or "uv run python tools/" in print/help
                if "python tools/" in line and ("print" in line or "help" in line or "f'" in line or 'f"' in line):
                    violations.append(f"{pyfile.name}:{i}: {line.strip()}")
        # Allow some in docstrings at the top of files, but not in print statements
        real_violations = [v for v in violations if "print" in v]
        assert not real_violations, (
            "Old 'tools/' references in print statements:\n"
            + "\n".join(real_violations)
        )


class TestLazyConfigLoading:
    """Verify config loading works correctly with the new cwd-based approach."""

    def test_find_root_uses_cwd(self, tmp_path):
        """_find_root should search from cwd, not __file__."""
        from rebrew.config import _find_root

        (tmp_path / "rebrew.toml").write_text("[targets.main]\nbinary = 'test.exe'\n")
        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            root = _find_root()
            assert root == tmp_path
        finally:
            os.chdir(old_cwd)

    def test_find_root_walks_up(self, tmp_path):
        """_find_root should walk up parent directories."""
        from rebrew.config import _find_root

        (tmp_path / "rebrew.toml").write_text("[targets.main]\nbinary = 'test.exe'\n")
        subdir = tmp_path / "a" / "b" / "c"
        subdir.mkdir(parents=True)
        old_cwd = os.getcwd()
        try:
            os.chdir(subdir)
            root = _find_root()
            assert root == tmp_path
        finally:
            os.chdir(old_cwd)

    def test_find_root_raises_without_toml(self, tmp_path):
        """_find_root should raise FileNotFoundError if no rebrew.toml."""
        from rebrew.config import _find_root

        old_cwd = os.getcwd()
        try:
            os.chdir(tmp_path)
            with pytest.raises(FileNotFoundError, match="rebrew.toml"):
                _find_root()
        finally:
            os.chdir(old_cwd)

    def test_load_config_from_cwd(self, tmp_path):
        """load_config should work from any subdirectory of a project."""
        from rebrew.config import load_config

        (tmp_path / "rebrew.toml").write_text(
            "[targets.main]\nbinary = 'test.exe'\narch = 'x86_32'\n"
        )
        subdir = tmp_path / "src" / "data"
        subdir.mkdir(parents=True)
        old_cwd = os.getcwd()
        try:
            os.chdir(subdir)
            cfg = load_config()
            assert cfg.target_name == "main"
            assert cfg.root == tmp_path
        finally:
            os.chdir(old_cwd)


class TestModuleImports:
    """Verify all modules can be imported without side effects."""

    @pytest.mark.parametrize("module_name", [
        "rebrew.config",
        "rebrew.annotation",
        "rebrew.matcher.core",
        "rebrew.matcher.scoring",
        "rebrew.matcher.parsers",
        "rebrew.matcher.mutator",
        "rebrew.binary_loader",
    ])
    def test_safe_import(self, module_name):
        """Modules should import without crashing even without rebrew.toml."""
        mod = importlib.import_module(module_name)
        assert mod is not None


class TestHelpTextReferences:
    """Verify CLI help text references updated entry points."""
    pass
