"""Tests for rebrew.errors — the shared base of every public error type."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rebrew.errors import RebrewError
from rebrew.ghidra import McpError
from rebrew.metadata_model import MetadataValidationError
from rebrew.recompile_client import RecompileError
from rebrew.registry import RegistryError
from rebrew.toolchain import ToolchainError

# Exception bases a rebrew error may carry besides RebrewError.
_STDLIB_EXCEPTION_BASES = {"Exception", "RuntimeError", "ValueError", "OSError"}


def _package_root() -> Path:
    """The installed-in-place ``src/rebrew`` directory."""
    import rebrew

    return Path(rebrew.__file__).parent


def _error_classes() -> list[tuple[Path, ast.ClassDef]]:
    """Every public ``*Error`` class defined in the package, by source file."""
    found: list[tuple[Path, ast.ClassDef]] = []
    for path in sorted(_package_root().rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not node.name.endswith("Error") or node.name.startswith("_"):
                continue
            if node.name == "RebrewError":  # the base itself
                continue
            base_names = {b.id for b in node.bases if isinstance(b, ast.Name)}
            # A class with no exception base (e.g. the JsonRpcError payload
            # dataclass) is not part of the raise hierarchy.
            if not base_names:
                continue
            found.append((path, node))
    return found


class TestRebrewErrorBase:
    def test_is_an_exception(self) -> None:
        assert issubclass(RebrewError, Exception)

    @pytest.mark.parametrize(
        "exc_type",
        [ToolchainError, RecompileError, RegistryError, McpError, MetadataValidationError],
    )
    def test_documented_errors_share_the_base(self, exc_type: type[Exception]) -> None:
        assert issubclass(exc_type, RebrewError)

    def test_original_bases_are_preserved(self) -> None:
        """Consumers catching the pre-2.7 stdlib base keep working."""
        assert issubclass(ToolchainError, RuntimeError)
        assert issubclass(RegistryError, RuntimeError)
        assert issubclass(MetadataValidationError, ValueError)

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
        classes = _error_classes()
        assert classes, "no error classes found — the scan is broken, not the tree"
        local_names = {node.name for _, node in classes}
        orphans: list[str] = []
        for path, node in classes:
            base_names = {b.id for b in node.bases if isinstance(b, ast.Name)}
            if "RebrewError" in base_names or base_names & local_names:
                continue
            if base_names <= _STDLIB_EXCEPTION_BASES:
                orphans.append(f"{path.name}:{node.name}")
        assert not orphans, (
            "these error types are unreachable via `except RebrewError`; "
            f"add RebrewError as a base: {orphans}"
        )
