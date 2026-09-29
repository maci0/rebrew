"""Every shipped sandbox prefix is one the temp-dir sweep can see.

``temp_dirs.sweep_stale_temp_dirs`` only removes entries whose name starts with
a declared prefix, so a caller that invents one produces sandboxes nothing ever
reclaims.  This module reads the shipped callers rather than a hand-copied
list, so the convention is enforced by the suite instead of by review.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from rebrew.temp_dirs import _TEMP_DIR_PREFIXES

_SRC = Path(__file__).resolve().parent.parent / "src" / "rebrew"

#: ``writable_temp_dir("x")`` and ``make_sandbox_dir("x")``: both the direct
#: callers and the toolchain modules that hand a prefix to
#: :func:`rebrew.dosbox.make_sandbox_dir`.
_SANDBOX_FACTORIES = frozenset({"writable_temp_dir", "make_sandbox_dir"})


def _shipped_prefixes() -> set[str]:
    """Return every literal prefix passed to a sandbox factory in ``src/``."""
    found: set[str] = set()
    for path in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name not in _SANDBOX_FACTORIES or not node.args:
                continue
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.add(first.value)
    return found


class TestSandboxPrefixSweep:
    def test_every_shipped_prefix_is_swept(self) -> None:
        """No shipped caller creates a sandbox the sweep cannot reclaim."""
        undeclared = sorted(
            prefix for prefix in _shipped_prefixes() if not prefix.startswith(_TEMP_DIR_PREFIXES)
        )
        assert not undeclared, (
            "these prefixes create sandboxes no sweep can see; add them to "
            f"temp_dirs._TEMP_DIR_PREFIXES: {undeclared}"
        )

    def test_declared_prefixes_are_actually_used(self) -> None:
        """A declared prefix nothing creates is dead weight in the sweep."""
        shipped = _shipped_prefixes()
        unused = sorted(
            declared
            for declared in _TEMP_DIR_PREFIXES
            if not any(shipped_prefix.startswith(declared) for shipped_prefix in shipped)
        )
        assert not unused, f"declared prefixes no shipped caller uses: {unused}"


@pytest.mark.parametrize("prefix", sorted(_TEMP_DIR_PREFIXES))
class TestSweepRemovesEachPrefix:
    def test_abandoned_sandbox_is_removed(self, tmp_path: Path, prefix: str) -> None:
        from rebrew.temp_dirs import sweep_stale_temp_dirs

        stale = tmp_path / f"{prefix}gone"
        stale.mkdir()
        _backdate(stale)
        kept = tmp_path / f"{prefix}fresh"
        kept.mkdir()

        assert sweep_stale_temp_dirs(tmp_path, age_s=60) == [stale]
        assert not stale.exists()
        assert kept.exists()

    def test_foreign_sibling_survives(self, tmp_path: Path, prefix: str) -> None:
        """The sweep stays off dirs it does not own, prefix or not."""
        from rebrew.temp_dirs import sweep_stale_temp_dirs

        foreign = tmp_path / "someone-elses-build"
        foreign.mkdir()
        _backdate(foreign)

        assert sweep_stale_temp_dirs(tmp_path, age_s=60) == []
        assert foreign.exists()


def _backdate(path: Path) -> None:
    """Age *path*'s mtime past any sweep threshold."""
    import os

    old = 0.0
    os.utime(path, (old, old))
