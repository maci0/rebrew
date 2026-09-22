"""Tests for rebrew.errors — the shared base of every public error type."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rebrew.errors import RebrewError
from rebrew.ghidra import McpApplyAborted, McpError
from rebrew.metadata_model import MetadataValidationError
from rebrew.recompile_client import RecompileError
from rebrew.registry import RegistryError
from rebrew.toolchain import ToolchainError
from rebrew.workspace import WorkspaceNotFound

# Stdlib exception bases a rebrew error may carry besides RebrewError.  A class
# deriving from one of these is part of the raise hierarchy regardless of what
# it is named: `McpApplyAborted` and `WorkspaceNotFound` both escaped an
# earlier `*Error`-suffix scan.
_STDLIB_EXCEPTION_BASES = {
    "Exception",
    "FileNotFoundError",
    "KeyError",
    "LookupError",
    "NotImplementedError",
    "OSError",
    "RuntimeError",
    "TypeError",
    "ValueError",
}


def _package_root() -> Path:
    """The installed-in-place ``src/rebrew`` directory."""
    import rebrew

    return Path(rebrew.__file__).parent


def _exception_classes() -> list[tuple[Path, ast.ClassDef]]:
    """Every public exception class defined in the package, by source file.

    Membership is by base class, not by name: a class counts when it derives
    from a stdlib exception or from another class in this set.  Resolved to a
    fixpoint so a two-level hierarchy inside the package is followed.
    """
    all_classes: list[tuple[Path, ast.ClassDef]] = []
    for path in sorted(_package_root().rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                all_classes.append((path, node))

    exceptions = {"RebrewError"}
    while True:
        grown = {
            node.name
            for _, node in all_classes
            if _base_names(node) & (_STDLIB_EXCEPTION_BASES | exceptions)
        }
        if grown <= exceptions:
            break
        exceptions |= grown

    return [
        (path, node)
        for path, node in all_classes
        if node.name in exceptions and not node.name.startswith("_") and node.name != "RebrewError"
    ]


def _base_names(node: ast.ClassDef) -> set[str]:
    """Bare-name bases of *node* (dotted and generic bases are ignored)."""
    return {b.id for b in node.bases if isinstance(b, ast.Name)}


class TestRebrewErrorBase:
    def test_is_an_exception(self) -> None:
        assert issubclass(RebrewError, Exception)

    @pytest.mark.parametrize(
        "exc_type",
        [
            ToolchainError,
            RecompileError,
            RegistryError,
            McpError,
            McpApplyAborted,
            MetadataValidationError,
            WorkspaceNotFound,
        ],
    )
    def test_documented_errors_share_the_base(self, exc_type: type[Exception]) -> None:
        assert issubclass(exc_type, RebrewError)

    def test_original_bases_are_preserved(self) -> None:
        """Consumers catching the pre-2.7 stdlib base keep working."""
        assert issubclass(ToolchainError, RuntimeError)
        assert issubclass(RegistryError, RuntimeError)
        assert issubclass(MetadataValidationError, ValueError)
        assert issubclass(McpApplyAborted, RuntimeError)
        assert issubclass(WorkspaceNotFound, FileNotFoundError)

    def test_structured_fields_survive_the_new_base(self) -> None:
        exc = ToolchainError("nope", kind="missing", name="msvc-6.0", retryable=False)
        assert isinstance(exc, RebrewError)
        assert (exc.kind, exc.name, exc.retryable) == ("missing", "msvc-6.0", False)

    def test_one_except_clause_catches_every_public_error(self) -> None:
        with pytest.raises(RebrewError):
            raise RegistryError("dup", group="rebrew.toolchains", name="x")

    def test_retryable_reads_off_the_base_without_getattr(self) -> None:
        """Every rebrew error answers "may I retry?"; default is no."""
        assert RegistryError("dup").retryable is False
        assert ToolchainError("blip", kind="docker", retryable=True).retryable is True


class TestHierarchyCoverage:
    """Every public error type in the package inherits the shared base.

    AST-level so a new error class is caught without importing optional
    extras (angr, declib) that the suite does not install.
    """

    def test_no_public_error_escapes_rebrew_error(self) -> None:
        classes = _exception_classes()
        assert classes, "no exception classes found — the scan is broken, not the tree"

        by_name = {node.name: node for _, node in classes}
        reachable = {"RebrewError"}
        while True:
            grown = {name for name, node in by_name.items() if _base_names(node) & reachable}
            if grown <= reachable:
                break
            reachable |= grown

        orphans = sorted(
            f"{path.name}:{node.name}" for path, node in classes if node.name not in reachable
        )
        assert not orphans, (
            "these exception types are unreachable via `except RebrewError`; "
            f"add RebrewError as a base: {orphans}"
        )
