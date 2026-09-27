"""Public import surface — the unfrozen half of the release contract.

CONTRIBUTING.md keeps the Python import surface unfrozen but requires a
``**Breaking:**`` entry for a removal, move, or signature change.  Nothing
checked that, so a moved helper reached a release whenever its author forgot
the prefix.  These tests diff the surface against the last tag and hold the
notes to it.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.public_surface import diff_surfaces, public_surface, surface_at_ref

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "rebrew"
CHANGELOG = ROOT / "CHANGELOG.md"
BREAKING_PREFIX = "**Breaking:**"

#: Shortest symbol name worth matching against a note: a one-letter name
#: would match any prose.
_MIN_LEAF = 4


def _unreleased() -> str:
    text = CHANGELOG.read_text(encoding="utf-8")
    return text.split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]


def _last_tag() -> str:
    proc = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("expected a v* tag in CI (test job must fetch tags)")
        pytest.skip("no v* tags in this checkout")
    return proc.stdout.strip()


class TestSurfaceGate:
    def test_broken_symbols_are_flagged_and_named(self) -> None:
        """A removed or reshaped public name ships as ``**Breaking:**`` and by name.

        The consumer-facing half of the contract: a note that does not name the
        symbol cannot be acted on, and an unflagged move fails the import.
        """
        old = surface_at_ref(_last_tag(), PKG, cwd=ROOT)
        if old is None:
            pytest.skip(f"cannot read {_last_tag()} from this checkout")
        removed, changed, _ = diff_surfaces(old, public_surface(PKG))

        broken = {
            f"{module}.{name}": module for module, names in removed.items() for name in names
        } | {f"{module}.{name}": module for module, names in changed.items() for name in names}
        if not broken:
            pytest.skip("no public surface change since the last tag")

        notes = _unreleased()
        assert BREAKING_PREFIX in notes, (
            "the public import surface changed but CHANGELOG.md has no "
            f"{BREAKING_PREFIX} entry under [Unreleased]: {sorted(broken)}\n"
            "CONTRIBUTING.md: a removal, move, or signature change there ships in "
            "a minor with a **Breaking:** entry naming the old and new import path."
        )
        unnamed = [
            symbol for symbol, module in sorted(broken.items()) if not _named(notes, symbol, module)
        ]
        assert unnamed == [], f"**Breaking:** entries do not name {unnamed}"


def _leaf(symbol: str) -> str:
    return symbol.rsplit(".", 1)[-1]


def _named(notes: str, symbol: str, module: str) -> bool:
    """A note names a symbol by its qualified path or by the part readers type."""
    leaf = _leaf(symbol)
    if len(leaf) >= _MIN_LEAF and (f"`{leaf}`" in notes or f" {leaf} " in notes):
        return True
    return f"`{module}`" in notes or f"`rebrew.{module}`" in notes


class TestBreakClassification:
    """The rule the gate applies, pinned so it cannot drift into noise."""

    def _surface(self, **names: str) -> dict[str, dict[str, tuple[str, ...]]]:
        return {
            "utils": {
                name: tuple(part.strip() for part in spec.split("|"))
                for name, spec in names.items()
            }
        }

    def _classify(self, before: str, after: str) -> tuple[bool, bool]:
        old, new = self._surface(f=before), self._surface(f=after)
        removed, changed, added = diff_surfaces(old, new)
        return bool(removed), bool(changed)

    def test_appended_optional_parameter_is_not_a_break(self) -> None:
        removed, changed = self._classify("def f|a: int|-> int", "def f|a: int|b: str = 'x'|-> int")
        assert (removed, changed) == (False, False)

    def test_option_added_mid_list_is_not_a_break(self) -> None:
        removed, changed = self._classify(
            "def f|a: int = 1|dry_run: bool = False|-> int",
            "def f|a: int = 1|json_output: bool = False|dry_run: bool = False|-> int",
        )
        assert (removed, changed) == (False, False)

    def test_dropped_parameter_is_a_break(self) -> None:
        _, changed = self._classify("def f|a: int|b: int|-> int", "def f|a: int|-> int")
        assert changed

    def test_new_required_parameter_is_a_break(self) -> None:
        _, changed = self._classify("def f|a: int|-> int", "def f|a: int|b: int|-> int")
        assert changed

    def test_changed_default_is_a_break(self) -> None:
        _, changed = self._classify("def f|a: int = 1|-> int", "def f|a: int = 2|-> int")
        assert changed

    def test_narrowed_return_is_a_break(self) -> None:
        _, changed = self._classify("def f|a: int|-> object", "def f|a: int|-> int")
        assert changed

    def test_renamed_parameter_is_a_break(self) -> None:
        _, changed = self._classify("def f|old: int|-> int", "def f|new: int|-> int")
        assert changed

    def test_changed_constant_is_a_break(self) -> None:
        removed, changed = self._classify("PAGE_SIZE = 100", "PAGE_SIZE = 50")
        assert not removed and changed

    def test_move_reads_as_removal_plus_addition(self) -> None:
        """A moved helper is the case the gate exists for: gone here, there now."""
        old = {"utils": {"helper": ("def helper", "!a: int", "")}}
        new = {"toolchain": {"helper": ("def helper", "!a: int", "")}}
        removed, changed, added = diff_surfaces(old, new)
        assert list(removed["utils"]) == ["helper"]
        assert list(added["toolchain"]) == ["helper"]
        assert changed == {}

    def test_module_constants_classes_and_methods_are_in_the_surface(self) -> None:
        source = {
            Path("src/rebrew/utils.py"): (
                "PAGE_SIZE = 100\n"
                "_private = 1\n"
                "class Pair(tuple[str, str]):\n"
                "    def render(self, width: int = 0) -> str:\n"
                "        return ''\n"
                "    def _hidden(self) -> None:\n"
                "        return None\n"
            )
        }
        surface = public_surface(Path("src/rebrew"), source=source)["utils"]
        assert surface["PAGE_SIZE"] == ("100",)
        assert surface["Pair"][0] == "class Pair"
        assert surface["Pair"][1] == "tuple[str, str]"
        assert surface["Pair.render"][0] == "def render"
        assert "_private" not in surface
        assert "Pair._hidden" not in surface

    def test_intra_package_reexport_is_in_the_surface(self) -> None:
        """A name re-exported is importable, so it is public whether or not it is local."""
        source = {
            Path("src/rebrew/utils.py"): "from .text import fold_ident\nfrom . import toolchain\n",
            Path("src/rebrew/__init__.py"): "from rebrew.config import load_config\n",
        }
        surface = public_surface(Path("src/rebrew"), source=source)
        assert surface["utils"]["fold_ident"] == ("re-export from .text",)
        assert surface["utils"]["toolchain"] == ("re-export from .",)
        assert surface[""]["load_config"] == ("re-export from rebrew.config",)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
