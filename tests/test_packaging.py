"""Packaging contract — what the wheel/sdist must declare and ship.

Static checks against pyproject.toml / MANIFEST.in / packaged data files.
CI's ``package`` job still builds and smoke-installs the wheel; this module
pins the metadata honesty rules that keep that artifact PyPI-safe.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
MANIFEST = ROOT / "MANIFEST.in"
PKG = ROOT / "src" / "rebrew"


def _project() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]


class TestPackagingMetadata:
    def test_version_is_dynamic_from_package(self) -> None:
        proj = _project()
        assert "version" not in proj
        assert "version" in proj.get("dynamic", [])
        init = (PKG / "__init__.py").read_text(encoding="utf-8")
        assert '__version__ = "' in init

    def test_requires_python_matches_ci_floor(self) -> None:
        assert _project()["requires-python"] == ">=3.13"

    def test_license_file_ships(self) -> None:
        proj = _project()
        assert proj.get("license") == "MIT"
        assert (ROOT / "LICENSE").is_file()
        assert "LICENSE" in proj.get("license-files", ["LICENSE"])

    def test_optional_dependencies_are_pypi_safe(self) -> None:
        """Wheel Requires-Dist must not carry git/path/direct-URL pins.

        Path (resembl) and git (m2c) deps belong in [dependency-groups] so a
        ``pip install rebrew[…]`` cannot resolve the wrong PyPI name or fail
        Warehouse's direct-URL rejection.
        """
        extras = _project().get("optional-dependencies", {})
        assert "similarity" not in extras
        assert "m2c" not in extras
        for name, deps in extras.items():
            for dep in deps:
                assert "@" not in dep, f"extra {name!r} has direct URL: {dep}"
                assert "git+" not in dep, f"extra {name!r} has git URL: {dep}"

    def test_non_pypi_deps_live_in_dependency_groups(self) -> None:
        data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        groups = data.get("dependency-groups", {})
        assert "similarity" in groups
        assert "m2c" in groups
        assert any(d == "resembl" or d.startswith("resembl") for d in groups["similarity"])
        assert any("git+" in d or "@" in d for d in groups["m2c"])


class TestPackagedDataFiles:
    def test_runtime_package_data_present_on_disk(self) -> None:
        assert (PKG / "AGENTS.md.template").is_file()
        assert (PKG / "PRINCIPLES.md").is_file()
        assert (PKG / "py.typed").is_file()
        skills = PKG / "agent-skills"
        assert skills.is_dir()
        skill_mds = list(skills.glob("*/SKILL.md"))
        assert len(skill_mds) >= 6, skill_mds

    def test_package_data_globs_cover_skills(self) -> None:
        data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        pkg_data = data["tool"]["setuptools"]["package-data"]["rebrew"]
        assert any("agent-skills" in g for g in pkg_data)
        assert "PRINCIPLES.md" in pkg_data
        assert any(g.endswith("py.typed") or g == "py.typed" for g in pkg_data)


class TestSdistManifest:
    def test_prunes_dev_trees(self) -> None:
        text = MANIFEST.read_text(encoding="utf-8")
        for tree in ("tests", "docs", "tools", ".agents", ".github"):
            assert f"prune {tree}" in text, tree
