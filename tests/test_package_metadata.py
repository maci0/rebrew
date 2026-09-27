"""Declared-package contract — the wheel METADATA must match the source.

Two things break on a user's machine and nowhere else, so they need a gate
here rather than a report:

* a third-party top-level import in ``src/rebrew`` that no
  ``[project].dependencies`` / optional-extra line claims — the wheel
  installs cleanly, then the command that imports it dies with ImportError;
* a ``[project.scripts]`` target that no longer resolves (renamed module,
  dropped ``main_entry``) — pip writes a console script that fails on first
  run, and the only test run of it would be on someone else's box.

``check_sdist_wheel.py`` covers which *files* ship; this covers what the
metadata *declares*.
"""

from __future__ import annotations

import ast
import importlib
import re
import sys
import tomllib
from importlib.metadata import distribution
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "rebrew"

# A top-level module resolves to an installed distribution under its
# normalized (PEP 503) name, which is not always the import name.  Only the
# pairs that differ are listed; everything else must match its import name.
_IMPORT_NAME_TO_DISTRIBUTION = {
    "flirt": "python-flirt",
    "tree_sitter": "tree-sitter",
    "tree_sitter_c": "tree-sitter-c",
}

# Imported by the shipped package but backed by no requirement of its own.
# Each import site catches ImportError and degrades, so a wheel installed
# without the providing extra stays usable.  A new entry needs a one-line
# reason, and it must name the extra or tool env that does provide it.
_OPTIONAL_IMPORTS = {
    "angr": "prove extra; prove.py / doctor.py raise a clear error without it",
    "claripy": "prove extra; direct import in prove.py / doctor.py",
    "declib": "binsync extra; only rebrew.binsync.serial touches it",
    "git": "prove extra, angr's own dependency",
    "pypcode": "no requirement ships it: a `prove` extra install via angr, or a "
    "kuna tool env; decompiler.py probes uv tool roots and falls back",
    "rapidfuzz": "similarity dependency group, never in wheel METADATA",
    "resembl": "similarity dependency group, never in wheel METADATA",
}

# ``rebrew`` itself is the package under test, not a dependency of itself.
_LOCAL_IMPORTS = {"rebrew"}


def _pyproject() -> dict[str, object]:
    with (ROOT / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)


def _declared_distributions() -> set[str]:
    """Every distribution name the wheel METADATA can pull, across all extras."""
    project = _pyproject()["project"]
    assert isinstance(project, dict)
    specs: list[str] = list(project["dependencies"])
    for extra in project["optional-dependencies"].values():
        specs.extend(extra)
    names = set()
    for spec in specs:
        # Strip the version floor and any environment marker.
        requirement = spec.split(";", 1)[0]
        name = requirement.split("[", 1)[0].split(">", 1)[0]
        name = name.split("<", 1)[0].split("=", 1)[0].split("!", 1)[0]
        name = name.split("~", 1)[0].split(" ", 1)[0]
        if "@" in name:
            name = name.split("@", 1)[0]
        names.add(name.strip().lower())
    return names


def _top_level_imports() -> set[str]:
    """Top-level modules imported by anything under ``src/rebrew``."""
    found: set[str] = set()
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                found.add(node.module.split(".", 1)[0])
    return found


def _requirement_name(spec: str) -> str:
    """The distribution name of one requirement specifier, lowercased."""
    return re.split(r"[\s\[<>=!~@;]", spec, maxsplit=1)[0].strip().lower()


def _unpinned(specs: list[str]) -> list[str]:
    """Requirements a resolver can move without the manifest changing.

    A version specifier is a floor; a direct reference (``name @ url``) pins
    the artifact but says nothing about *which* revision of a moving VCS it
    is, so those are returned too and checked separately.
    """
    return [s for s in specs if not any(op in s for op in ("==", ">=", "~=", "<", ">", "!="))]


class TestDeclaredDependencies:
    def test_every_third_party_import_is_declared(self) -> None:
        """An import with no Requires-Dist line installs cleanly and fails at
        runtime, so the stdlib set comes from the running interpreter."""
        stdlib = set(sys.stdlib_module_names)
        declared = _declared_distributions()
        undeclared = set()
        for name in _top_level_imports():
            if name in stdlib or name in _LOCAL_IMPORTS or name in _OPTIONAL_IMPORTS:
                continue
            if name in declared or _IMPORT_NAME_TO_DISTRIBUTION.get(name, name) in declared:
                continue
            undeclared.add(name)
        assert not undeclared, (
            "imported but not declared in [project].dependencies or an extra "
            f"(add a floor, or an entry in _OPTIONAL_IMPORTS with its reason): "
            f"{sorted(undeclared)}"
        )

    def test_dependency_floors_are_present(self) -> None:
        """A bare requirement lets a resolver pick a version with a known
        advisory; every floor here tracks an audited uv.lock version."""
        project = _pyproject()["project"]
        assert isinstance(project, dict)
        floored = [
            spec
            for spec in project["dependencies"]
            if not any(op in spec for op in ("==", ">=", "~=", "<", ">", "!="))
        ]
        assert not floored, f"unversioned runtime requirements: {floored}"

    @pytest.mark.parametrize("extra", sorted(_pyproject()["project"]["optional-dependencies"]))
    def test_extra_floors_are_present(self, extra: str) -> None:
        """The extras ship in the wheel METADATA, so a bare name there resolves
        without the floor the runtime list carries.  A package pulled by an
        extra lands in the user's env under the same advisories."""
        assert not _unpinned(_pyproject()["project"]["optional-dependencies"][extra]), (
            f"unversioned requirements in the {extra} extra: "
            f"{_unpinned(_pyproject()['project']['optional-dependencies'][extra])}"
        )

    @pytest.mark.parametrize("group", sorted(_pyproject()["dependency-groups"]))
    def test_group_floors_are_present(self, group: str) -> None:
        """A dev group is resolved by `uv sync` on every contributor machine
        and in CI, so a bare name there is an unpinned advisory path too.

        Two requirements are legitimately bare: a `[tool.uv.sources]` entry
        pins the artifact itself, by path (the sibling ``resembl`` checkout)
        or by a commit-pinned direct reference (``m2c``).  A name that
        carries neither a version specifier nor a source is unpinned.
        """
        sources = _pyproject().get("tool", {}).get("uv", {}).get("sources", {})
        assert isinstance(sources, dict)
        unpinned = [
            spec
            for spec in _unpinned(_pyproject()["dependency-groups"][group])
            if " @ " not in spec and _requirement_name(spec) not in sources
        ]
        assert not unpinned, f"unversioned requirements in the {group} group: {unpinned}"

    def test_vcs_requirements_are_commit_pinned(self) -> None:
        """A git requirement is the one dependency a lock can silently re-point
        at a new commit: the URL survives, the content does not.  Every
        ``name @ git+…`` therefore ends in a full commit, never a branch, tag,
        or short SHA (uv resolves those on every sync)."""
        specs: list[str] = []
        for group in _pyproject()["dependency-groups"].values():
            specs.extend(group)
        for extra in _pyproject()["project"]["optional-dependencies"].values():
            specs.extend(extra)
        floating = [
            spec for spec in specs if " @ git+" in spec and not re.search(r"@[0-9a-f]{40}$", spec)
        ]
        assert not floating, f"git requirements not pinned to a commit: {floating}"


class TestDeclaredScripts:
    @staticmethod
    def _scripts() -> dict[str, str]:
        project = _pyproject()["project"]
        assert isinstance(project, dict)
        return project["scripts"]

    def test_every_script_target_resolves(self) -> None:
        """pip writes each console script unconditionally; a bad target only
        fails when the user runs it."""
        for name, target in self._scripts().items():
            module_name, _, attribute = target.partition(":")
            assert module_name.startswith("rebrew."), (
                f"{name}: entry point outside the package: {target}"
            )
            assert attribute, f"{name}: entry point has no attribute: {target}"
            module = importlib.import_module(module_name)
            assert hasattr(module, attribute), f"{name}: {module_name} has no {attribute}"

    def test_every_script_is_a_console_script(self) -> None:
        """A ``gui_scripts`` target would need a desktop entry; this is a
        terminal tool and ships no .desktop file."""
        entry_points = distribution("rebrew").entry_points
        assert entry_points, "rebrew is not installed with entry points"
        assert {ep.group for ep in entry_points} == {"console_scripts"}

    @pytest.mark.parametrize("name", sorted(_pyproject()["project"]["scripts"]))
    def test_script_name_is_prefixed_rebrew(self, name: str) -> None:
        """Every executable lands in PATH, so the prefix is what keeps them
        from colliding with another tool."""
        assert name == "rebrew" or name.startswith("rebrew-"), name
