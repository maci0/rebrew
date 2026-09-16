"""Packaging contract — what the wheel/sdist must declare and ship.

Static checks against pyproject.toml / MANIFEST.in / packaged data files.
CI's ``package`` job still builds and smoke-installs the wheel; this module
pins the metadata honesty rules that keep that artifact PyPI-safe.
"""

from __future__ import annotations

import re
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

    def test_changelog_opens_with_unreleased_or_current_version(self) -> None:
        """Keep a Changelog: notes land under Unreleased until the tag bump.

        The dated ``[version]`` section must exist for every released
        ``__version__``; between tags the file opens with ``[Unreleased]``.
        """
        from rebrew import __version__

        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        assert f"## [{__version__}]" in text
        first = next(line for line in text.splitlines() if line.startswith("## "))
        assert first == "## [Unreleased]" or first.startswith(f"## [{__version__}]")

    def test_every_git_tag_has_a_changelog_section(self) -> None:
        """Release tags must keep their dated notes (no swallowed sections).

        Past cuts dropped ``## [0.3.0]`` / ``## [0.9.0]`` headers into the
        next release body; this pins the tag→section contract so it cannot
        happen again without a failing packaging test.
        """
        import subprocess

        proc = subprocess.run(
            ["git", "tag", "-l", "v*"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        tags = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        assert tags, "expected at least one v* tag"
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        missing = [t for t in tags if f"## [{t.lstrip('v')}]" not in text]
        assert missing == [], f"CHANGELOG.md missing sections for tags: {missing}"

    def test_contributing_major_line_matches_package(self) -> None:
        from rebrew import __version__

        major = __version__.split(".", 1)[0]
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        assert f"Rebrew is {major}.x." in text

    def test_requires_python_matches_ci_floor(self) -> None:
        assert _project()["requires-python"] == ">=3.13"
        assert (ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.13"

    def test_build_system_pins_exact_setuptools(self) -> None:
        """Isolated ``uv build`` resolves build-system.requires from PyPI.

        A range would let a new setuptools patch change wheel layout without
        a lockfile bump; keep the pin exact and below the 81 cut line.
        """
        data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        requires = data["build-system"]["requires"]
        assert requires == ["setuptools==80.10.2"], requires
        assert data["build-system"]["build-backend"] == "setuptools.build_meta"

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

    def test_direct_dep_floors_match_lock(self) -> None:
        """pyproject floors must equal the audited lock versions.

        A lock-free install resolves the floor; keeping it equal to ``uv.lock``
        means ``pip install rebrew`` cannot pull an older advisory this tree
        already left behind.  When bumping the lock, bump the floor in the
        same change.
        """
        data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        lock_text = (ROOT / "uv.lock").read_text(encoding="utf-8")
        locked: dict[str, str] = {}
        cur: str | None = None
        for line in lock_text.splitlines():
            if line.startswith("name = "):
                cur = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("version = ") and cur and cur not in locked:
                locked[cur] = line.split("=", 1)[1].strip().strip('"')

        floor_re = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+)\s*>=\s*(?P<floor>[0-9][0-9A-Za-z._+]*)")
        decls: list[str] = list(data["project"]["dependencies"])
        for extra_deps in data["project"].get("optional-dependencies", {}).values():
            decls.extend(extra_deps)
        for group_deps in data.get("dependency-groups", {}).values():
            decls.extend(group_deps)

        checked = 0
        for decl in decls:
            if "git+" in decl or decl.strip() == "resembl":
                continue
            m = floor_re.match(decl.split("#", 1)[0].strip())
            if m is None:
                continue
            lock_name = m.group("name").lower().replace("_", "-")
            floor = m.group("floor")
            assert lock_name in locked, f"{lock_name} missing from uv.lock"
            assert locked[lock_name] == floor, (
                f"{lock_name}: floor {floor} != lock {locked[lock_name]}"
            )
            checked += 1
        assert checked >= 20, checked


class TestCycloneDxSbom:
    def test_generate_sbom_from_lock(self) -> None:
        from tools.generate_sbom import _project_version, build_bom

        bom = build_bom((ROOT / "uv.lock").read_text(encoding="utf-8"), _project_version())
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.5"
        assert bom["metadata"]["component"]["name"] == "rebrew"
        names = {c["name"] for c in bom["components"]}
        assert "httpx" in names
        assert "typer" in names
        assert "rebrew" not in names
        # Registry wheels carry sha256 hashes in the lock.
        hashed = [c for c in bom["components"] if c.get("hashes")]
        assert len(hashed) > 10
        for c in bom["components"]:
            assert c["purl"].startswith("pkg:")
            assert c["version"]


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
        for tree in (
            "tests",
            "docs",
            "tools",
            ".agents",
            ".github",
            ".scratch",
            ".cache",
            "build",
            "dist",
            ".venv",
            "venv",
        ):
            assert f"prune {tree}" in text, tree
