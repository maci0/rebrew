"""Public import surface — the unfrozen half of the release contract.

CONTRIBUTING.md keeps the Python import surface unfrozen but requires a
``**Breaking:**`` entry for a removal, move, or signature change.  Nothing
checked that, so a moved helper reached a release whenever its author forgot
the prefix.  These tests diff the surface against the last tag and hold the
notes to it.  ``TestDashboardRoutes`` does the same for the dashboard's route
table, the other half CONTRIBUTING holds unfrozen.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tools.public_surface import (
    dashboard_routes,
    diff_surfaces,
    public_surface,
    routes_at_ref,
    surface_at_ref,
)

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "rebrew"
CHANGELOG = ROOT / "CHANGELOG.md"
BREAKING_PREFIX = "**Breaking:**"

#: Shortest symbol name worth matching against a note: a one-letter name
#: would match any prose.
_MIN_LEAF = 4


def _section(text: str, heading: str) -> str:
    """The body under *heading*, up to the next ``## `` heading."""
    return text.split(heading, 1)[1].split("\n## [", 1)[0]


def _unreleased() -> str:
    """The notes that have not shipped yet.

    ``[Unreleased]`` plus — on the release commit, before the tag exists — the
    dated section for the version being cut.  Notes move there when
    ``__version__`` is bumped, and the surface delta they describe is the same
    one: reading only ``[Unreleased]`` made the gate fail on every release
    commit, and a gate that must be ignored at the one moment it matters is not
    a gate.  Once ``v<version>`` is tagged the section is frozen history and
    drops out, so a later change cannot borrow an old entry.
    """
    from rebrew import __version__

    text = CHANGELOG.read_text(encoding="utf-8")
    notes = _section(text, "## [Unreleased]")
    tagged = subprocess.run(
        ["git", "tag", "--list", f"v{__version__}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if not tagged.stdout.strip():
        heading = f"## [{__version__}]"
        if heading in text:
            notes += _section(text, heading)
    return notes


def _last_tag() -> str:
    proc = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
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
        current = public_surface(PKG)
        removed, changed, added = diff_surfaces(old, current)

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
        leaves: dict[str, set[str]] = {}
        for module, names in added.items():
            for name in names:
                leaves.setdefault(_leaf(name), set()).add(module)
        unnamed = [
            symbol
            for symbol, module in sorted(broken.items())
            if not _named(
                notes,
                symbol,
                module,
                _destination(leaves, symbol),
                module_emptied=not current.get(module),
            )
        ]
        assert unnamed == [], f"**Breaking:** entries do not name {unnamed}"


def _leaf(symbol: str) -> str:
    return symbol.rsplit(".", 1)[-1]


def _spellings(symbol: str) -> tuple[str, ...]:
    """The dotted paths a note may use for a symbol, longest first.

    A method is written ``Class.method`` far more often than ``module.Class.method``,
    so every trailing run of components counts, with or without its call suffix.
    """
    parts = symbol.split(".")
    return tuple(
        f"{'.'.join(parts[index:])}()" if callable_suffix else ".".join(parts[index:])
        for index in range(len(parts))
        for callable_suffix in (False, True)
    )


def _named(
    notes: str,
    symbol: str,
    module: str,
    moved_to: str | None = None,
    module_emptied: bool = True,
) -> bool:
    """A note names a symbol by its qualified path or by the part readers type.

    The spellings are the ones a note actually uses: the bare name, the name
    called as it is at the call site (`` `to_dict()` ``), the qualified path
    (`` `ProjectConfig.to_dict` ``), or the module holding it.  2.14.0 removed
    ``ProjectConfig.to_dict`` and wrote `` `ProjectConfig.to_dict()` ``, which
    the bare-name test below missed, so a correctly documented break scored as
    undocumented; a gate that cries wolf on a correct note is one an author
    learns to route around.

    A move is named by its destination, so the new module counts too.  The
    notes are required to give "the old and new import path" (CONTRIBUTING),
    and the destination is the half a reader needs.  A move therefore drops
    the origin module: a note about a different symbol that happens to say
    `` `utils` `` did not name the five names that left it, and 2.17.0's
    `rebrew.temp_dirs` split sailed through the gate on that mention.

    A module names a symbol that vanished from it only when nothing public is
    left in the module (``module_emptied``), which is the one note the module
    can stand in for.  While the module keeps exporting, a mention is a
    sentence about something else, and `rebrew.verify` lost
    ``DEFAULT_TOOLCHAIN`` unannounced on a `verify-cache` note that happened to
    name the module.
    """
    leaf = _leaf(symbol)
    if len(leaf) >= _MIN_LEAF and any(
        spelling in notes for spelling in (f"`{leaf}`", f"`{leaf}()`", f" {leaf} ")
    ):
        return True
    if any(f"`{part}`" in notes for part in _spellings(symbol)):
        return True
    named_module = moved_to if moved_to is not None else module
    if moved_to is None and not module_emptied:
        return False
    paths: tuple[str, ...] = (named_module, f"rebrew.{named_module}")
    return any(f"`{path}`" in notes for path in paths)


def _destination(leaves: dict[str, set[str]], symbol: str) -> str | None:
    """The one module a moved name now lives in, or ``None`` when it did not move.

    A name that vanishes here and reappears under a single other module is a
    move; the same leaf name added to two modules is a coincidence, and the
    note has to name the symbol itself.
    """
    targets = leaves.get(_leaf(symbol), set()) - {symbol.rsplit(".", 1)[0]}
    return next(iter(targets)) if len(targets) == 1 else None


class TestNoteNaming:
    """How a note spells a symbol, pinned against the spellings notes use.

    The gate fails the build on an unnamed break, so a correct note that the
    matcher cannot read is the expensive failure: 2.14.0 removed
    ``ProjectConfig.to_dict`` and wrote `` `ProjectConfig.to_dict()` ``, which
    the bare-name spelling did not match.
    """

    def test_name_written_as_a_call_names_the_symbol(self) -> None:
        assert _named("call `to_dict()` instead", "config.ProjectConfig.to_dict", "config")

    def test_qualified_path_names_the_symbol(self) -> None:
        assert _named("`ProjectConfig.to_dict` is gone", "config.ProjectConfig.to_dict", "config")

    def test_module_path_names_the_symbol(self) -> None:
        assert _named("nothing public left in `rebrew.exports`", "exports.main", "exports")

    def test_destination_module_names_a_moved_symbol(self) -> None:
        assert _named(
            "now `rebrew.verify_exports`", "exports.compare_exports", "exports", "verify_exports"
        )

    def test_origin_module_does_not_name_a_moved_symbol(self) -> None:
        """A note about another name in the old module is not a migration path.

        The `rebrew.temp_dirs` split: `utils` is named in the notes for a
        re-export that is gone, and five names left it, so counting the origin
        module let the break through undocumented.
        """
        assert not _named(
            "nothing public is re-exported through `utils` now",
            "utils.writable_temp_dir",
            "utils",
            "temp_dirs",
        )

    def test_unrelated_prose_does_not_name_the_symbol(self) -> None:
        assert not _named("the exports table grew a column", "exports.compare_exports", "exports")

    def test_a_module_still_exporting_does_not_name_one_name_it_lost(self) -> None:
        """Naming the module is only a note for a module that went private.

        `rebrew.verify` still exports the rest of what `verify_hash` owns, so
        its `DEFAULT_TOOLCHAIN` re-export needed its own entry, and a sentence
        about the verify cache is not one.
        """
        assert not _named(
            "`verify` reported the entry from its cache",
            "verify.DEFAULT_TOOLCHAIN",
            "verify",
            module_emptied=False,
        )

    def test_a_module_that_went_private_still_names_what_it_lost(self) -> None:
        assert _named(
            "nothing public is left in `exports`",
            "exports.compare_exports",
            "exports",
            module_emptied=True,
        )

    def test_a_name_in_two_new_modules_is_not_a_destination(self) -> None:
        leaves = {"helper": {"toolchain", "utils"}, "main": {"toolchain"}}
        assert _destination(leaves, "renamed.helper") is None
        assert _destination(leaves, "renamed.main") == "toolchain"


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

    def test_widened_parameter_annotation_is_not_a_break(self) -> None:
        """``typer.Option(None, ...)`` passed ``None`` whatever the annotation said.

        ``_classify`` splits its spec on ``|``, which a union annotation spells,
        so the descriptor is built here instead.
        """
        old = {"utils": {"f": ("def f", "!va: str=typer(None, '--va')", "-> None")}}
        new = {"utils": {"f": ("def f", "!va: str | None=typer(None, '--va')", "-> None")}}
        removed, changed, added = diff_surfaces(old, new)
        assert (removed, changed, added) == ({}, {}, {})

    def test_widened_return_annotation_is_a_break(self) -> None:
        """A caller reading the result gets a value it did not get before."""
        old = {"utils": {"f": ("def f", "a: int", "-> int")}}
        new = {"utils": {"f": ("def f", "a: int", "-> int | None")}}
        _, changed, _ = diff_surfaces(old, new)
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
            Path("src/rebrew/text.py"): "def fold_ident(name: str) -> str:\n    return name\n",
            Path("src/rebrew/__init__.py"): "from rebrew.config import load_config\n",
            Path(
                "src/rebrew/config.py"
            ): "def load_config(path: str) -> dict[str, str]:\n    return {}\n",
        }
        surface = public_surface(Path("src/rebrew"), source=source)
        assert surface["utils"]["fold_ident"] == surface["text"]["fold_ident"]
        assert "toolchain" in surface["utils"]
        assert surface[""]["load_config"] == surface["config"]["load_config"]

    def test_absolute_intra_package_import_is_a_reexport(self) -> None:
        """The spelling this tree writes everywhere, not only the relative one.

        ``from rebrew.utils import untrusted_text`` is as importable as
        ``from .utils import untrusted_text``; scoring only the relative form
        made every such alias invisible, and the sibling it stopped importing
        then read as a removal.
        """
        source = {
            Path(
                "src/rebrew/utils.py"
            ): "def helper(value: object) -> str:\n    return str(value)\n",
            Path("src/rebrew/cli.py"): "from rebrew.utils import helper\n",
        }
        surface = public_surface(Path("src/rebrew"), source=source)
        assert surface["cli"]["helper"] == surface["utils"]["helper"]

    def test_a_move_into_a_sibling_that_keeps_importing_it_is_not_a_break(self) -> None:
        """``from rebrew.cli import name`` keeps working, so no import path changed."""
        root = Path("src/rebrew")
        old = public_surface(
            root,
            source={
                Path(
                    "src/rebrew/cli.py"
                ): "def helper(value: object) -> str:\n    return str(value)\n"
            },
        )
        new = public_surface(
            root,
            source={
                Path(
                    "src/rebrew/utils.py"
                ): "def helper(value: object) -> str:\n    return str(value)\n",
                Path("src/rebrew/cli.py"): "from rebrew.utils import helper\n",
            },
        )
        removed, changed, added = diff_surfaces(old, new)
        assert removed == {} and changed == {}
        assert list(added["utils"]) == ["helper"]

    def test_a_reshaped_definition_still_breaks_at_the_importing_module(self) -> None:
        """The alias carries the origin's shape, so a changed signature shows up."""
        root = Path("src/rebrew")
        old = public_surface(
            root,
            source={
                Path(
                    "src/rebrew/utils.py"
                ): "def helper(value: object) -> str:\n    return str(value)\n",
                Path("src/rebrew/cli.py"): "from rebrew.utils import helper\n",
            },
        )
        new = public_surface(
            root,
            source={
                Path("src/rebrew/utils.py"): "def helper(value: object, strict: bool) -> str:\n"
                "    return str(value)\n",
                Path("src/rebrew/cli.py"): "from rebrew.utils import helper\n",
            },
        )
        removed, changed, _ = diff_surfaces(old, new)
        assert removed == {}
        assert list(changed["utils"]) == ["helper"]
        assert list(changed["cli"]) == ["helper"]

    def test_a_third_party_import_is_not_a_reexport(self) -> None:
        """That name is not rebrew's to move or reshape, and no sibling defines it."""
        source = {
            Path("src/rebrew/cli.py"): "from rich.console import Console\nfrom os import environ\n"
        }
        surface = public_surface(Path("src/rebrew"), source=source)
        assert surface["cli"] == {}

    def test_default_named_by_a_module_constant_is_compared_by_value(self) -> None:
        """Naming a constant is not a signature change; moving its value is.

        ``max_size: int = 9999`` written as ``max_size: int = NO_MAX_SIZE``
        accepts the same calls, so the gate must not demand a ``**Breaking:``**
        note for it.  A constant whose value moved is a real break and still
        reads as one.
        """
        root = Path("src/rebrew")

        def _signature(skeleton: str) -> tuple[str, ...]:
            source = {
                Path("src/rebrew/skeleton.py"): f"NO_MAX_SIZE = 9999\n\n{skeleton}\n",
                Path("src/rebrew/match.py"): (
                    "from rebrew.skeleton import NO_MAX_SIZE\n\n"
                    "def main(max_size: int = NO_MAX_SIZE) -> None:\n    return None\n"
                ),
            }
            surface = public_surface(root, source=source)
            return surface["skeleton"]["filter_by_size"] + surface["match"]["main"]

        literal = _signature("def filter_by_size(max_size: int = 9999) -> None:\n    return None\n")
        named = _signature(
            "def filter_by_size(max_size: int = NO_MAX_SIZE) -> None:\n    return None\n"
        )
        assert named == literal

        lowered = public_surface(
            root,
            source={
                Path("src/rebrew/skeleton.py"): (
                    "NO_MAX_SIZE = 4096\n\ndef filter_by_size(max_size: int = NO_MAX_SIZE) -> None:\n"
                    "    return None\n"
                )
            },
        )["skeleton"]["filter_by_size"]
        _, changed, _ = diff_surfaces(
            {"skeleton": {"filter_by_size": literal[:3]}},
            {"skeleton": {"filter_by_size": lowered[:3]}},
        )
        assert changed

    def test_unresolvable_default_keeps_its_name(self) -> None:
        """A computed binding has no value to read, so the name is what compares."""
        source = {
            Path("src/rebrew/utils.py"): (
                "from os import environ\n"
                "PAGE_SIZE = int(environ.get('PAGE_SIZE', '100'))\n"
                "\n"
                "def page(size: int = PAGE_SIZE) -> int:\n    return size\n"
            )
        }
        surface = public_surface(Path("src/rebrew"), source=source)["utils"]
        assert surface["page"] == ("def page", "size: int=PAGE_SIZE", "-> int")

    def test_redundant_keyword_in_a_constant_is_not_a_break(self) -> None:
        """``is_group=False`` repeated in the table is the field's own default.

        A component table is a tuple of constructor calls compared as text, so
        deleting the redundant keyword read as a changed value and demanded a
        ``**Breaking:**`` note for a spelling nobody can observe.  A keyword
        carrying a *different* value is what a consumer sees, and still reads as
        a change.
        """
        root = Path("src/rebrew")
        plugin = (
            "from dataclasses import dataclass\n\n"
            "@dataclass(frozen=True)\n"
            "class CliComponent:\n"
            "    name: str\n"
            "    panel: str = 'dev'\n"
            "    is_group: bool = False\n"
        )

        def _table(is_group: str, panel: str) -> tuple[str, ...]:
            source = {
                Path("src/rebrew/plugin.py"): plugin,
                Path("src/rebrew/builtins.py"): (
                    "from rebrew.plugin import CliComponent\n\n"
                    "BUILTIN_COMPONENTS = (\n"
                    f"    CliComponent(name='diff', panel={panel}{is_group}),\n"
                    ")\n"
                ),
            }
            return public_surface(root, source=source)["builtins"]["BUILTIN_COMPONENTS"]

        spelled = _table(", is_group=False", "'dev'")
        dropped = _table("", "'dev'")
        assert spelled == dropped
        assert "is_group" not in dropped[0]

        _, changed, _ = diff_surfaces(
            {"builtins": {"BUILTIN_COMPONENTS": spelled}},
            {"builtins": {"BUILTIN_COMPONENTS": _table("", "'sync'")}},
        )
        assert changed
        _, changed, _ = diff_surfaces(
            {"builtins": {"BUILTIN_COMPONENTS": spelled}},
            {"builtins": {"BUILTIN_COMPONENTS": _table(", is_group=True", "'dev'")}},
        )
        assert changed


class TestDashboardRoutes:
    """Reading the dashboard's route table, and the gate over its delta.

    CONTRIBUTING.md holds the ``/api/*`` JSON unfrozen but requires a
    ``**Breaking:**`` entry for a removed route, and nothing read the table:
    only the Python import surface was checked, so a route the browser's
    ``get()`` still called could go out unflagged.
    """

    def test_union_of_frozensets_and_a_named_path_reads(self) -> None:
        source = (
            '_FAVICON = "/favicon.svg"\n'
            '_API = frozenset({"/api/targets"})\n'
            '_EXTRA = frozenset({"/api/health"})\n'
            '_KNOWN_ROUTES = (frozenset({"/", _FAVICON}) | _API) | _EXTRA\n'
        )
        assert dashboard_routes(source) == frozenset(
            {"/", "/favicon.svg", "/api/targets", "/api/health"}
        )

    def test_a_computed_table_reads_as_nothing(self) -> None:
        """An unreadable table must not score as a table with no routes."""
        assert dashboard_routes("_KNOWN_ROUTES = frozenset(_PATHS)\n") is None
        assert dashboard_routes("_PATHS = ['/api/targets']\n") is None

    def test_the_shipped_table_reads(self) -> None:
        source = (PKG / "dashboard.py").read_text(encoding="utf-8")
        routes = dashboard_routes(source)
        assert routes is not None
        # The removal gate above skips whenever nothing was dropped, so the
        # table's own contents are checked here against what the handler
        # actually dispatches: a route that vanishes from the literal table
        # without leaving the dispatch is a silent drop.
        dispatched = set(re.findall(r'path == "(/[^"]*)"', source))
        assert dispatched, "no literal route dispatch found in dashboard.py"
        assert dispatched <= routes, sorted(dispatched - routes)

    def test_removed_route_ships_as_breaking_and_by_path(self) -> None:
        old = routes_at_ref(_last_tag(), cwd=ROOT)
        if old is None:
            pytest.skip(f"cannot read {_last_tag()} from this checkout")
        current = dashboard_routes((PKG / "dashboard.py").read_text(encoding="utf-8"))
        if current is None:
            pytest.fail("the route table is no longer spelled as literals")
        removed = sorted(old - current)
        if not removed:
            pytest.skip("no dashboard route removed since the last tag")

        notes = _unreleased()
        assert BREAKING_PREFIX in notes, (
            f"the dashboard dropped {removed} but CHANGELOG.md has no "
            f"{BREAKING_PREFIX} entry under [Unreleased]"
        )
        unnamed = [path for path in removed if path not in notes]
        assert unnamed == [], f"**Breaking:** entries do not name {unnamed}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__]))
