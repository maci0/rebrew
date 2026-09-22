"""Packaging contract — what the wheel/sdist must declare and ship.

Static checks against pyproject.toml / MANIFEST.in / packaged data files.
CI's ``package`` job still builds and smoke-installs the wheel; this module
pins the metadata honesty rules that keep that artifact PyPI-safe.
"""

from __future__ import annotations

import os
import re
import tomllib
from pathlib import Path

import pytest

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
        if not tags:
            # CI's test job sets fetch-tags: true on actions/checkout so this
            # contract actually runs on every PR.  Skipping only for shallow
            # local clones that never fetched tags.
            if os.environ.get("GITHUB_ACTIONS"):
                pytest.fail("expected v* tags in CI (test job checkout must set fetch-tags: true)")
            pytest.skip("no v* tags in this checkout (shallow/CI clone fetches none)")
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        missing = [t for t in tags if f"## [{t.lstrip('v')}]" not in text]
        assert missing == [], f"CHANGELOG.md missing sections for tags: {missing}"

    def test_unreleased_uses_each_changelog_group_once(self) -> None:
        """``[Unreleased]`` has at most one Added/Changed/Removed/Fixed group.

        Repeated groups scatter the next release's ``**Breaking:**`` entries,
        and a heading glued to its first bullet (``### Added- ...``) renders
        the entry as a heading.
        """
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        unreleased = text.split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
        heads = re.findall(r"^### (.*)$", unreleased, flags=re.M)
        bad = [h for h in heads if h not in ("Added", "Changed", "Removed", "Fixed")]
        bad += [f"repeated {h}" for h in set(heads) if heads.count(h) > 1]
        assert bad == [], bad

    def test_contributing_major_line_matches_package(self) -> None:
        from rebrew import __version__

        major = __version__.split(".", 1)[0]
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        assert f"Rebrew is {major}.x." in text

    def test_coverage_db_bump_since_last_tag_is_breaking_in_unreleased(self) -> None:
        """CONTRIBUTING: coverage.db version bumps need ``**Breaking:**`` notes.

        Between tags ``__version__`` stays pinned; schema bumps land under
        ``## [Unreleased]`` and must be labeled Breaking (``--force`` rebuild
        migration), matching schema ``"7"`` in 2.4.0.
        """
        import subprocess

        from rebrew.build_db import _CURRENT_DB_VERSION

        tag_proc = subprocess.run(
            ["git", "describe", "--tags", "--abbrev=0"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if tag_proc.returncode != 0 or not tag_proc.stdout.strip():
            if os.environ.get("GITHUB_ACTIONS"):
                pytest.fail("expected a v* tag in CI (test job must fetch tags)")
            pytest.skip("no git tags in this checkout")
        last_tag = tag_proc.stdout.strip()
        show = subprocess.run(
            ["git", "show", f"{last_tag}:src/rebrew/build_db.py"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if show.returncode != 0:
            pytest.skip(f"cannot read build_db.py at {last_tag}")
        tagged = re.search(r'_CURRENT_DB_VERSION\s*=\s*"([^"]+)"', show.stdout)
        if tagged is None:
            pytest.skip(f"no _CURRENT_DB_VERSION at {last_tag}")
        if tagged.group(1) == _CURRENT_DB_VERSION:
            return

        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        first = next(line for line in text.splitlines() if line.startswith("## "))
        assert first == "## [Unreleased]", (
            f"coverage.db bumped {_CURRENT_DB_VERSION!r} past {last_tag} "
            f"({tagged.group(1)!r}) but CHANGELOG does not open with [Unreleased]"
        )
        unreleased = text.split("## [Unreleased]", 1)[1]
        next_hdr = unreleased.find("\n## [")
        if next_hdr != -1:
            unreleased = unreleased[:next_hdr]
        assert "**Breaking:**" in unreleased, (
            f"coverage.db {_CURRENT_DB_VERSION!r} (was {tagged.group(1)!r} at "
            f"{last_tag}) must have a **Breaking:** entry under [Unreleased]"
        )
        assert _CURRENT_DB_VERSION in unreleased, (
            f"[Unreleased] Breaking notes must name db_version {_CURRENT_DB_VERSION!r}"
        )
        assert "coverage.db" in unreleased or "db_version" in unreleased

    def test_requires_python_matches_ci_floor(self) -> None:
        assert _project()["requires-python"] == ">=3.13"
        python_version = (ROOT / ".python-version").read_text(encoding="utf-8").strip()
        assert re.fullmatch(r"3\.13\.\d+", python_version)
        # The package job takes the shared action's default python-version.
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        package_job = workflow.split("\n  package:\n", 1)[1].split("\n  cli-contract:\n", 1)[0]
        assert "uses: ./.github/actions/uv-env" in package_job
        assert "python-version:" not in package_job
        action = (ROOT / ".github/actions/uv-env/action.yml").read_text(encoding="utf-8")
        assert f'default: "{python_version}"' in action

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

    def test_classifiers_declare_typed_console_package(self) -> None:
        """Wheel METADATA must advertise PEP 561 + CLI audience honestly.

        ``py.typed`` already ships via package-data; without ``Typing :: Typed``
        PyPI / type-checkers treat the distribution as untyped at the index
        level.  Console + Developers match the installed artifact (73 console
        scripts, no GUI).
        """
        classifiers = set(_project()["classifiers"])
        assert "Typing :: Typed" in classifiers
        assert "Environment :: Console" in classifiers
        assert "Intended Audience :: Developers" in classifiers

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

    def test_extra_install_hints_name_the_distribution(self) -> None:
        """Missing-extra hints must name the git source the README installs from.

        rebrew is not published to PyPI, so a bare ``pip install 'rebrew[…]'``
        resolves a PyPI name this project does not own, and does not reach the
        ``uv tool install`` venv. Editable ``.[extra]`` hints strand anyone
        without a source tree beside them.
        """
        from rebrew.binsync.serial import _DECLIB_MISSING_MSG
        from rebrew.prove import _ANGR_MISSING_MSG

        git = "@ git+https://github.com/maci0/rebrew.git'"
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        assert "uv tool install git+https://github.com/maci0/rebrew.git" in readme
        assert f"uv tool install --reinstall 'rebrew[prove] {git}" in _ANGR_MISSING_MSG
        assert f"uv tool install --reinstall 'rebrew[binsync] {git}" in _DECLIB_MISSING_MSG
        assert f"'rebrew[prove] {git}" in readme
        for text in (_ANGR_MISSING_MSG, _DECLIB_MISSING_MSG, readme):
            assert "pip install 'rebrew[" not in text
            assert 'install -e ".[' not in text

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
        assert any(g.startswith("agent-skills/") for g in pkg_data)
        assert "PRINCIPLES.md" in pkg_data
        assert any(g.endswith("py.typed") or g == "py.typed" for g in pkg_data)
        assert "**/py.typed" in pkg_data
        # All skill assets (not only *.md) so a non-markdown reference ships.
        assert "agent-skills/**/*" in pkg_data

    def test_project_urls_include_issues_and_changelog(self) -> None:
        urls = _project()["urls"]
        assert urls["Homepage"].startswith("https://github.com/")
        assert urls["Issues"].endswith("/issues")
        assert "CHANGELOG" in urls["Changelog"]
        assert urls["Security"].endswith("/SECURITY.md")

    def test_readme_long_description_links_are_absolute(self) -> None:
        """PyPI renders README.md as the long description; relative links 404.

        Keep markdown hrefs absolute (``https://github.com/maci0/rebrew/...``)
        so the wheel METADATA description stays navigable off-repo.
        """
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        relative = re.findall(r"\[[^\]]*\]\((?!https?://|mailto:|#)([^)]+)\)", text)
        assert relative == [], f"README has relative markdown links: {relative}"

    def test_exclude_package_data_drops_subpackage_agents(self) -> None:
        """matcher/catalog AGENTS.md are contributor docs, not runtime assets."""
        data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
        excluded = data["tool"]["setuptools"]["exclude-package-data"]["rebrew"]
        assert "**/AGENTS.md" in excluded
        assert (PKG / "matcher" / "AGENTS.md").is_file()
        assert (PKG / "catalog" / "AGENTS.md").is_file()


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
            ".hypothesis",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            "build",
            "dist",
            ".venv",
            "venv",
            "rebrew.egg-info",
            "src/rebrew.egg-info",
        ):
            assert f"prune {tree}" in text, tree
        assert "recursive-exclude src/rebrew AGENTS.md" in text
        assert "global-exclude .coverage" in text

    def test_built_sdist_omits_egg_info_residue(self, tmp_path: Path) -> None:
        """setuptools egg-info bulk must not ship; SOURCES.txt alone is OK.

        A src/ layout places egg-info next to the package.  Without an explicit
        MANIFEST prune the residue (PKG-INFO, entry_points, requires.txt)
        lands in the sdist.  setuptools always force-appends
        ``<egg-info>/SOURCES.txt`` after prune — that single file is the
        recorded manifest and is expected.  Build into tmp_path so this stays
        offline-friendly when the pinned setuptools wheel is already cached.
        """
        import os
        import subprocess
        import tarfile

        out = tmp_path / "dist"
        out.mkdir()
        env = os.environ.copy()
        env.update(
            {
                "SOURCE_DATE_EPOCH": "0",
                "TZ": "UTC",
                "LC_ALL": "C",
                "PYTHONHASHSEED": "0",
            }
        )
        proc = subprocess.run(
            ["uv", "build", "--sdist", "--out-dir", str(out)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        assert proc.returncode == 0, proc.stderr or proc.stdout
        sdists = list(out.glob("*.tar.gz"))
        assert len(sdists) == 1, sdists
        with tarfile.open(sdists[0]) as tf:
            names = tf.getnames()
        egg_files = [n for n in names if ".egg-info/" in n or n.endswith(".egg-info")]
        # Directory entry + SOURCES.txt only — no duplicated metadata files.
        bad = [
            n for n in egg_files if not n.endswith(".egg-info") and not n.endswith("SOURCES.txt")
        ]
        assert bad == [], f"sdist contains egg-info residue: {bad}"
        assert any(n.endswith("SOURCES.txt") for n in egg_files), egg_files
        # setuptools force-writes an empty egg_info stub into the sdist after
        # MANIFEST processing (same class as SOURCES.txt) — accept only that
        # harmless form, never a real setuptools config.
        setup_cfgs = [n for n in names if n.endswith("/setup.cfg") or n.endswith("setup.cfg")]
        if setup_cfgs:
            assert len(setup_cfgs) == 1, setup_cfgs
            with tarfile.open(sdists[0]) as tf:
                raw = tf.extractfile(setup_cfgs[0])
                assert raw is not None
                body = raw.read().decode()
            assert body.strip() == "[egg_info]\ntag_build = \ntag_date = 0"

    def test_built_wheel_ships_skill_tree_and_typing_marker(self, tmp_path: Path) -> None:
        """Wheel must carry every on-disk skill asset plus Typing :: Typed."""
        import os
        import subprocess
        import zipfile

        out = tmp_path / "dist"
        out.mkdir()
        env = os.environ.copy()
        env.update(
            {
                "SOURCE_DATE_EPOCH": "0",
                "TZ": "UTC",
                "LC_ALL": "C",
                "PYTHONHASHSEED": "0",
            }
        )
        proc = subprocess.run(
            ["uv", "build", "--wheel", "--out-dir", str(out)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        assert proc.returncode == 0, proc.stderr or proc.stdout
        wheels = list(out.glob("*.whl"))
        assert len(wheels) == 1, wheels
        with zipfile.ZipFile(wheels[0]) as zf:
            names = set(zf.namelist())
            meta = zf.read(next(n for n in names if n.endswith(".dist-info/METADATA"))).decode()
        skills_root = PKG / "agent-skills"
        missing = [
            f"rebrew/agent-skills/{p.relative_to(skills_root).as_posix()}"
            for p in skills_root.rglob("*")
            if p.is_file()
            and f"rebrew/agent-skills/{p.relative_to(skills_root).as_posix()}" not in names
        ]
        assert missing == [], f"wheel missing skill assets: {missing}"
        assert "rebrew/py.typed" in names
        assert "Typing :: Typed" in meta
        assert "Environment :: Console" in meta
        assert "Project-URL: Security," in meta
        assert any(n.endswith("/licenses/LICENSE") for n in names)
        assert "rebrew/matcher/AGENTS.md" not in names
        assert "rebrew/catalog/AGENTS.md" not in names
