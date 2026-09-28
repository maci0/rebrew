"""Packaging contract — what the wheel/sdist must declare and ship.

Static checks against pyproject.toml / MANIFEST.in / packaged data files.
CI's ``package`` job still builds and smoke-installs the wheel; this module
pins the metadata honesty rules that keep that artifact PyPI-safe.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tools import release_check

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
MANIFEST = ROOT / "MANIFEST.in"
PKG = ROOT / "src" / "rebrew"

_BREAKING_PREFIX = "- **Breaking:** "

CHANGELOG_GROUPS = ("Added", "Changed", "Removed", "Fixed", "Performance")

_GLUED_HEADING = re.compile(r"^### (" + "|".join(CHANGELOG_GROUPS) + r")- (.*)$")

# Dev-only trees MANIFEST.in must keep out of the sdist.  ``test_prunes_dev_trees``
# checks the manifest text; ``test_built_sdist_omits_dev_trees_and_egg_info_residue``
# checks the archive those lines are supposed to produce.
_PRUNED_DEV_TREES = (
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
)


def _norm_changelog_line(line: str) -> str:
    """Ignore a Breaking label so a prefixed line still matches the tagged notes."""
    if line.startswith(_BREAKING_PREFIX):
        return "- " + line[len(_BREAKING_PREFIX) :]
    return line


def _expand_glued_heading(line: str) -> list[str]:
    """Split ``### Fixed- **entry.** rest`` into the heading and the bullet.

    A heading glued to its first bullet is a formatting slip, not a claim:
    reflowing it into ``### Fixed`` plus ``- **entry.** rest`` says nothing
    the tagged notes did not already say, so the frozen-section check has to
    match the reflowed form.  Only a tag written before
    ``test_no_section_glues_a_group_heading_to_its_bullet`` can carry one.
    """
    match = _GLUED_HEADING.match(line)
    if match is None:
        return [line]
    return [f"### {match.group(1)}", f"- {match.group(2)}"]


def _changelog_section(body: str, version: str) -> str | None:
    """Body of ``## [version]`` up to the next release heading, or None."""
    match = re.search(rf"^## \[{re.escape(version)}\](?: - |\s*$)", body, re.M)
    if match is None:
        return None
    rest = body[match.end() :]
    nxt = re.search(r"^## \[", rest, re.M)
    return rest if nxt is None else rest[: nxt.start()]


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
            check=False,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            if os.environ.get("GITHUB_ACTIONS"):
                pytest.fail(f"git tag failed in CI: {proc.stderr.strip()}")
            pytest.skip("not a git checkout (source archive)")
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

    def test_each_version_has_exactly_one_changelog_section(self) -> None:
        """Two ``## [x.y.z]`` headings split one release's notes in half.

        ``make release-check`` counts the entries of the first
        ``## [<version>]`` it finds and every consumer reads the first one
        too, so a second heading for the same version (an abandoned cut whose
        heading stayed below the older releases) makes the rest of the notes
        unreachable and lets the release ship with a partial section.
        """
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        counts: dict[str, int] = {}
        for match in re.finditer(r"^## \[(\d+\.\d+\.\d+)\]", text, flags=re.M):
            counts[match.group(1)] = counts.get(match.group(1), 0) + 1
        repeated = sorted(v for v, n in counts.items() if n > 1)
        assert repeated == [], f"CHANGELOG.md has more than one section for: {repeated}"

    def test_patch_release_never_ships_a_breaking_entry(self) -> None:
        """A patch carries fixes; a behavior change needs at least a minor.

        ``CONTRIBUTING.md`` lets the library import surface break in a minor
        with a ``**Breaking:**`` entry, never in a patch, where a consumer
        pinning ``~=2.13.1`` would take the break without a version signal.
        No patch in the tag history carries one, so this is a real invariant
        rather than a new rule: it fails when a patch release edits behavior
        its ``x.y.z`` patch number promises it did not.
        """
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        offenders = [
            m.group(1)
            for m in re.finditer(
                r"^## \[(\d+\.\d+\.\d+)\][^\n]*$(.*?)(?=^## \[|\Z)", text, flags=re.M | re.S
            )
            if int(m.group(1).rsplit(".", 1)[1]) != 0 and "**Breaking:**" in m.group(2)
        ]
        assert offenders == [], f"patch release(s) carry a **Breaking:** entry: {offenders}"

    def test_unreleased_uses_each_changelog_group_once(self) -> None:
        """``[Unreleased]`` has at most one Added/Changed/Removed/Fixed group.

        Repeated groups scatter the next release's ``**Breaking:**`` entries,
        and a heading glued to its first bullet (``### Added- ...``) renders
        the entry as a heading.
        """
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        unreleased = text.split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
        heads = re.findall(r"^### (.*)$", unreleased, flags=re.M)
        bad = [h for h in heads if h not in CHANGELOG_GROUPS]
        bad += [f"repeated {h}" for h in set(heads) if heads.count(h) > 1]
        assert bad == [], bad

    def test_no_section_glues_a_group_heading_to_its_bullet(self) -> None:
        """A group heading is a heading in every section, not just Unreleased.

        ``## [2.14.0]`` shipped ``### Fixed- **`make format-check` passes
        again.** Four test modules had drifted from``, so the entry and the
        four fixes that follow it rendered as one multi-line H3: the release
        notes a consumer reads for that tag had no ``Fixed`` group they could
        find, and every bullet under the glued heading looked like part of
        its title.  The Unreleased group check missed it because it only read
        the staged block, and a section only grows wrong at the release cut,
        where that block has just been emptied.
        """
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        bad = [h for h in re.findall(r"^### (.*)$", text, flags=re.M) if h not in CHANGELOG_GROUPS]
        assert bad == [], f"changelog heading glued to its bullet: {bad}"

    def test_unreleased_repeats_no_entry(self) -> None:
        """``[Unreleased]`` lists every change exactly once.

        A merge of two release-prep branches landed 38 copies of the same
        bullets in the section, so a reader counted one change several times
        and the next release note was roughly twice the work it described.
        The first line of an entry is its identity: two entries that open the
        same way describe the same change.
        """
        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        unreleased = text.split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
        opens = re.findall(r"^- (.*)$", unreleased, flags=re.M)
        assert len(opens) == len(set(opens)), sorted({o for o in opens if opens.count(o) > 1})

    def test_notes_added_after_the_tag_stay_unreleased(self) -> None:
        """A bullet written after the tag must not land in that tag's section.

        ``## [2.9.0]`` once gained entries for commits that came after the
        tag, so the published notes described code the release does not
        contain. A line may gain a ``**Breaking:**`` prefix, and a line may
        move up under ``[Unreleased]``. A released section may not grow a
        line the tag's changelog did not have.
        """
        import subprocess
        from collections import Counter

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
            ["git", "show", f"{last_tag}:CHANGELOG.md"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if show.returncode != 0:
            pytest.skip(f"cannot read CHANGELOG.md at {last_tag}")

        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        unreleased = text.split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
        unreleased_lines = {
            _norm_changelog_line(line) for line in unreleased.splitlines() if line.strip()
        }
        headings = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", show.stdout, flags=re.M)
        for version in headings:
            tagged = _changelog_section(show.stdout, version)
            current = _changelog_section(text, version)
            assert tagged is not None and current is not None
            tag_lines = [
                expanded
                for line in tagged.splitlines()
                if line.strip()
                for expanded in _expand_glued_heading(_norm_changelog_line(line))
            ]
            cur_lines = [
                _norm_changelog_line(line) for line in current.splitlines() if line.strip()
            ]
            index = 0
            for line in tag_lines:
                if index < len(cur_lines) and cur_lines[index] == line:
                    index += 1
            assert index == len(cur_lines), (
                f"## [{version}] has lines {last_tag}'s changelog does not:\n"
                + "\n".join(cur_lines[index:])
            )
            dropped = list((Counter(tag_lines) - Counter(cur_lines)).elements())
            stray = [line for line in dropped if line not in unreleased_lines]
            assert stray == [], (
                f"## [{version}] dropped notes that are not under [Unreleased]:\n"
                + "\n".join(stray)
            )

    def test_contributing_major_line_matches_package(self) -> None:
        from rebrew import __version__

        major = __version__.split(".", 1)[0]
        text = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        assert f"Rebrew is {major}.x." in text

    def test_console_script_dropped_since_last_tag_is_breaking(self) -> None:
        """CONTRIBUTING: the script names are frozen from 1.0.0.

        A ``[project.scripts]`` key that disappears (a rename writes a new key
        and drops the old) is a rename for whoever calls the script, so each
        dropped name needs a ``**Breaking:**`` entry naming it. Three renames
        in the 2.13.1 delta shipped with only one of them written down.
        """
        import subprocess

        from rebrew import __version__

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
            ["git", "show", f"{last_tag}:pyproject.toml"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        if show.returncode != 0:
            pytest.skip(f"cannot read pyproject.toml at {last_tag}")
        tagged_scripts = tomllib.loads(show.stdout)["project"].get("scripts", {})

        dropped = sorted(set(tagged_scripts) - set(_project().get("scripts", {})))
        if not dropped:
            return

        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        if __version__ != last_tag.lstrip("v"):
            section_hdr = f"## [{__version__}]"
            assert section_hdr in text, f"CHANGELOG.md has no {section_hdr} section"
            block = text.split(section_hdr, 1)[1]
        else:
            first = next(line for line in text.splitlines() if line.startswith("## "))
            assert first == "## [Unreleased]", (
                f"{last_tag} dropped the console scripts {', '.join(dropped)} but "
                f"CHANGELOG does not open with [Unreleased]"
            )
            block = text.split("## [Unreleased]", 1)[1]
        next_hdr = block.find("\n## [")
        if next_hdr != -1:
            block = block[:next_hdr]

        undeclared = [name for name in dropped if name not in block]
        assert undeclared == [], (
            f"console script(s) dropped since {last_tag} with no **Breaking:** "
            f"entry naming them under [Unreleased] or [{__version__}]: "
            f"{', '.join(undeclared)}"
        )

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

        from rebrew import __version__

        text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        if __version__ != last_tag.lstrip("v"):
            section_hdr = f"## [{__version__}]"
            assert section_hdr in text, f"CHANGELOG.md has no {section_hdr} section"
            target_block = text.split(section_hdr, 1)[1]
        else:
            first = next(line for line in text.splitlines() if line.startswith("## "))
            assert first == "## [Unreleased]", (
                f"coverage.db bumped {_CURRENT_DB_VERSION!r} past {last_tag} "
                f"({tagged.group(1)!r}) but CHANGELOG does not open with [Unreleased]"
            )
            target_block = text.split("## [Unreleased]", 1)[1]

        next_hdr = target_block.find("\n## [")
        if next_hdr != -1:
            target_block = target_block[:next_hdr]
        assert "**Breaking:**" in target_block, (
            f"coverage.db {_CURRENT_DB_VERSION!r} (was {tagged.group(1)!r} at "
            f"{last_tag}) must have a **Breaking:** entry under [Unreleased] or [{__version__}]"
        )
        assert _CURRENT_DB_VERSION in target_block, (
            f"Breaking notes must name db_version {_CURRENT_DB_VERSION!r}"
        )
        assert "coverage.db" in target_block or "db_version" in target_block

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
        constraints = (ROOT / "build-constraints.txt").read_text(encoding="utf-8")
        st_ver = requires[0].removeprefix("setuptools==")
        assert f"setuptools=={st_ver} " in constraints, (
            f"build-constraints.txt missing setuptools=={st_ver} pin from pyproject.toml"
        )

    def test_license_file_ships(self) -> None:
        proj = _project()
        assert proj.get("license") == "MIT"
        assert (ROOT / "LICENSE").is_file()
        assert "LICENSE" in proj.get("license-files", ["LICENSE"])
        assert "NOTICE" in proj["license-files"]
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        # Wheel consumers need the optional copyleft grants traced to upstream.
        for needle in (
            "resembl",
            "GPLv3",
            "GPL-3.0-only",
            "m2c",
            "aa869da289a565c68f701e734bd74606f1bd5ed4",
            "pyvex",
            "BSD-2-Clause AND GPL-2.0-or-later",
            "LibVEX",
        ):
            assert needle in notice, needle

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
        assert "--editable '/path/to/rebrew[prove]'" in _ANGR_MISSING_MSG
        assert "uv sync --extra prove" not in _ANGR_MISSING_MSG
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
        component = bom["metadata"]["component"]
        assert component["name"] == "rebrew"
        assert component["licenses"] == [{"license": {"id": "MIT"}}]
        assert component["purl"] == f"pkg:github/maci0/rebrew@v{component['version']}"
        assert component["bom-ref"] == component["purl"]
        refs = {(item["type"], item["url"]) for item in component["externalReferences"]}
        assert refs == {
            ("vcs", "https://github.com/maci0/rebrew"),
            ("website", "https://github.com/maci0/rebrew"),
            ("issue-tracker", "https://github.com/maci0/rebrew/issues"),
            ("release-notes", "https://github.com/maci0/rebrew/blob/main/CHANGELOG.md"),
            ("advisories", "https://github.com/maci0/rebrew/blob/main/SECURITY.md"),
        }
        by_name = {c["name"]: c for c in bom["components"]}
        # resembl states the trove text "GPLv3"; recording the SPDX id it does
        # not write would put a license claim in a release artifact.
        assert by_name["resembl"]["licenses"] == [{"license": {"name": "GPLv3"}}]
        assert by_name["m2c"]["licenses"] == [{"expression": "GPL-3.0-only"}]
        assert by_name["pyvex"]["licenses"] == [{"expression": "BSD-2-Clause AND GPL-2.0-or-later"}]
        assert by_name["certifi"]["licenses"] == [{"expression": "MPL-2.0"}]
        assert by_name["hypothesis"]["licenses"] == [{"expression": "MPL-2.0"}]
        # The declarations above are the locked artifacts' own.  A lock bump
        # that changes one has to update NOTICE too.  resembl (similarity
        # group) and pyvex (prove extra) are absent from a default `uv sync`
        # and from `uv sync --all-extras` respectively, so check each against
        # the installed artifact only where it is installed: the SBOM itself is
        # built from the lock and needs no environment.
        import importlib.metadata as importlib_metadata

        installed: dict[str, Any] = {}
        for dist in ("resembl", "pyvex", "certifi", "hypothesis"):
            try:
                installed[dist] = importlib_metadata.metadata(dist)
            except importlib_metadata.PackageNotFoundError:
                continue
        if "resembl" in installed:
            assert installed["resembl"].get("License") == "GPLv3"
        if "pyvex" in installed:
            assert installed["pyvex"].get("License-Expression") == (
                "BSD-2-Clause AND GPL-2.0-or-later"
            )
        # certifi and hypothesis ride every resolve, so this asserts the loop
        # above saw the environment rather than skipping over it.
        assert {"certifi", "hypothesis"} <= set(installed)
        # certifi predates PEP 639 and still uses the free-text field.
        assert installed["certifi"].get("License") == "MPL-2.0"
        assert installed["certifi"].get("License-Expression") is None
        assert installed["hypothesis"].get("License-Expression") == "MPL-2.0"
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

    def test_every_component_carries_its_declared_license(self) -> None:
        """A component with no license field reads to a scanner as public domain.

        The grants come from tools/licenses.py, each transcribed from the pinned
        artifact's own METADATA; a lock bump that adds a package must add its
        row there or `make sbom` fails rather than emitting a blank field.
        """
        from tools.generate_sbom import _project_version, build_bom

        bom = build_bom((ROOT / "uv.lock").read_text(encoding="utf-8"), _project_version())
        for component in bom["components"]:
            (entry,) = component["licenses"]
            assert entry.keys() & {"expression", "license"}, component["name"]

    def test_validator_rejects_an_unlicensed_component(self) -> None:
        from tools.generate_sbom import MIN_COMPONENTS, validate_bom

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": "rebrew"}},
            "components": [
                {"name": f"p{i}", "licenses": [{"expression": "MIT"}]}
                for i in range(MIN_COMPONENTS)
            ],
        }
        validate_bom(bom)
        bom["components"][3] = {"name": "blank"}
        with pytest.raises(ValueError, match="without a license"):
            validate_bom(bom)

    def test_license_table_covers_the_lock_exactly(self) -> None:
        """`uv lock --upgrade` adds a distribution; an unrecorded grant means the
        released SBOM and NOTICE both describe a tree nobody reviewed."""
        from tools.licenses import PATH_OR_GIT_LICENSES, REGISTRY_LICENSES

        lock_text = (ROOT / "uv.lock").read_text(encoding="utf-8")
        registry: set[str] = set()
        by_name: dict[str, str] = {}
        for block in lock_text.split("[[package]]")[1:]:
            name = re.search(r'^name = "(.*)"', block, re.M)
            version = re.search(r'^version = "(.*)"', block, re.M)
            source = re.search(r"^source = (.*)$", block, re.M)
            assert name, block
            if version is None:
                # The editable self-package; its version lives in the wheel.
                continue
            by_name.setdefault(name.group(1), version.group(1))
            if source and "registry" in source.group(1):
                registry.add(f"{name.group(1)}=={version.group(1)}")

        assert set(REGISTRY_LICENSES) == registry, {
            "unrecorded": sorted(registry - set(REGISTRY_LICENSES)),
            "stale": sorted(set(REGISTRY_LICENSES) - registry),
        }
        non_registry = {
            name
            for name in by_name
            if f"{name}=={by_name[name]}" not in registry and name != "rebrew"
        }
        assert set(PATH_OR_GIT_LICENSES) == non_registry, sorted(non_registry)
        recorded = dict(REGISTRY_LICENSES) | PATH_OR_GIT_LICENSES
        for key, value in recorded.items():
            assert value.strip(), key

    def test_generated_bom_passes_its_own_validator(self) -> None:
        """`make sbom` gates on this, so the real lock must clear it."""
        from tools.generate_sbom import _project_version, build_bom, validate_bom

        validate_bom(build_bom((ROOT / "uv.lock").read_text(encoding="utf-8"), _project_version()))

    def test_validator_rejects_an_empty_inventory(self) -> None:
        """A BOM that inventories nothing reads to a scanner as a clean result."""
        from tools.generate_sbom import MIN_COMPONENTS, validate_bom

        empty = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"component": {"name": "rebrew"}},
            "components": [],
        }
        with pytest.raises(ValueError, match=f"at least {MIN_COMPONENTS}"):
            validate_bom(empty)

    def test_validator_rejects_a_wrong_format_or_spec(self) -> None:
        from tools.generate_sbom import validate_bom

        base = {
            "metadata": {"component": {"name": "rebrew"}},
            "components": [{"name": "x"}] * 10,
        }
        with pytest.raises(ValueError, match="bomFormat"):
            validate_bom({**base, "bomFormat": "SPDX", "specVersion": "1.5"})
        with pytest.raises(ValueError, match="specVersion"):
            validate_bom({**base, "bomFormat": "CycloneDX", "specVersion": "1.4"})
        with pytest.raises(ValueError, match="metadata.component"):
            validate_bom({**base, "bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {}})


class TestWheelSmokeScript:
    """The package job runs tools/smoke_wheel_install.py under the wheel's own
    interpreter, so the script has to be runnable that way and has to name the
    file it cannot find."""

    def test_runs_clean_against_an_installed_package(self) -> None:
        """The CI invocation, end to end: exit 0 and the version on stderr."""
        import rebrew

        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "smoke_wheel_install.py")],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "rebrew" in result.stderr
        assert str(Path(rebrew.__file__).resolve().parent) in result.stderr

    def test_names_every_missing_runtime_file(self, tmp_path: Path) -> None:
        """A wheel that imports but ships no agent-skills must fail the gate."""
        import rebrew
        from tools.smoke_wheel_install import RUNTIME_ENTRIES, check

        package = tmp_path / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        monkey = pytest.MonkeyPatch()
        monkey.setattr(rebrew, "__file__", str(package / "__init__.py"))
        try:
            missing = check()
        finally:
            monkey.undo()
        assert [message.split(" ", 2)[2] for message in missing] == [
            str(package / entry) for entry, _ in RUNTIME_ENTRIES
        ]

    def test_names_a_skill_directory_without_a_manifest(self, tmp_path: Path) -> None:
        """A wheel carrying ``agent-skills/`` but no ``SKILL.md`` installs and
        imports, then ships an empty ``rebrew skills list``."""
        import rebrew
        from tools.smoke_wheel_install import RUNTIME_ENTRIES, check

        package = tmp_path / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        for entry, kind in RUNTIME_ENTRIES:
            path = package / entry
            if kind == "dir":
                path.mkdir(parents=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("", encoding="utf-8")
        (package / "agent-skills" / "rebrew-workflow").mkdir()
        (package / "agent-skills" / "rebrew-init").mkdir()
        (package / "agent-skills" / "rebrew-init" / "SKILL.md").write_text("", encoding="utf-8")
        monkey = pytest.MonkeyPatch()
        monkey.setattr(rebrew, "__file__", str(package / "__init__.py"))
        try:
            missing = check()
        finally:
            monkey.undo()
        assert missing == [
            f"missing file {package / 'agent-skills' / 'rebrew-workflow' / 'SKILL.md'}"
        ]

    def test_every_expected_runtime_entry_is_declared(self) -> None:
        from tools.smoke_wheel_install import RUNTIME_ENTRIES

        entries = dict(RUNTIME_ENTRIES)
        assert entries["agent-skills"] == "dir"
        assert entries["AGENTS.md.template"] == "file"
        assert entries["PRINCIPLES.md"] == "file"
        assert entries["py.typed"] == "file"
        assert entries["workspace/py.typed"] == "file"
        # The install gate has to cover the marker the METADATA claims, or a
        # wheel that dropped it still passes and every consumer's type-checker
        # sees an untyped rebrew.
        assert "Typing :: Typed" in _project()["classifiers"]
        # The script must assert exactly what the source tree ships, or the
        # wheel gate quietly stops covering a packaged runtime file.
        package = ROOT / "src" / "rebrew"
        for entry, kind in RUNTIME_ENTRIES:
            path = package / entry
            assert path.is_dir() if kind == "dir" else path.is_file(), path

    def test_every_copyleft_dependency_is_named_in_the_sbom(self) -> None:
        """A copyleft package absent from ``_COPYLEFT_EXPRESSIONS`` is unattributed.

        The SBOM names copyleft components by hand because ``uv.lock`` records
        no license.  The three expressions above are asserted individually,
        which cannot catch a *new* one: a lock bump that pulls in another
        reciprocal-license package would ship a CycloneDX document that calls
        the whole tree MIT-permissive, and NOTICE would stop being a complete
        attribution.  Resolve the environment instead and require every
        copyleft distribution found there to be declared.
        """
        from tools.generate_sbom import (
            _COPYLEFT_EXPRESSIONS,
            copyleft_names_in_environment,
        )

        found = copyleft_names_in_environment()
        # resembl / pyvex / m2c live in non-default groups, so they are absent
        # from a plain `uv sync`. certifi and hypothesis are not, and without
        # them the loop below would never run and the gate would be vacuous.
        assert {"certifi", "hypothesis"} <= {n for n, _ in found}, found
        undeclared = [(n, lic) for n, lic in found if n not in _COPYLEFT_EXPRESSIONS]
        assert undeclared == [], (
            "copyleft dependencies missing from _COPYLEFT_EXPRESSIONS (add the "
            "SPDX expression and a NOTICE entry): " + repr(undeclared)
        )


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

    def test_no_library_modules_have_shebangs(self) -> None:
        """Library modules in src/rebrew must not contain shebang lines.

        Installed entry point wrappers provide shebangs; in-package shebangs
        trigger distro package linter warnings (non-executable-script).
        """
        shebang_files = [
            p.relative_to(PKG).as_posix()
            for p in PKG.rglob("*.py")
            if p.read_text(encoding="utf-8").startswith("#!")
        ]
        assert shebang_files == [], f"library modules have shebangs: {shebang_files}"


class TestUserFacingDocPointers:
    """``docs/`` is pruned from the sdist and never enters the wheel.

    A message saying "see docs/TOOLCHAIN.md" names a file the installed
    package does not carry, and a scaffolded project has no ``docs/`` either.
    The packaged agent skills already qualify their pointers as "rebrew
    repo ``docs/…``"; gate the same wording on every string a user can read.
    """

    _POINTER = re.compile(r"docs/[A-Za-z0-9_.-]+\.md")

    @staticmethod
    def _user_facing_strings(path: Path) -> Iterator[tuple[int, str]]:
        """``(lineno, text)`` for every string literal that is not a docstring.

        Comments never reach the AST and a docstring is always the child of a
        bare ``Expr`` statement, so both contributor-facing forms drop out.
        """
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = {
            id(child)
            for parent in ast.walk(tree)
            if isinstance(parent, ast.Expr)
            for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
            ):
                yield node.lineno, node.value

    def test_console_doc_pointers_name_the_repo(self) -> None:
        unqualified = [
            f"{path.relative_to(ROOT)}:{lineno}"
            for path in sorted(PKG.rglob("*.py"))
            for lineno, text in self._user_facing_strings(path)
            if self._POINTER.search(text) and "rebrew repo" not in text
        ]
        assert unqualified == [], (
            "user-facing text points at a docs/ file the install does not ship; "
            f'qualify it as "the rebrew repo\'s docs/…": {unqualified}'
        )


class TestSdistManifest:
    def test_prunes_dev_trees(self) -> None:
        text = MANIFEST.read_text(encoding="utf-8")
        for tree in _PRUNED_DEV_TREES:
            assert f"prune {tree}" in text, tree
        assert "recursive-exclude src/rebrew AGENTS.md" in text
        assert "global-exclude .coverage" in text
        for doc in ("CHANGELOG.md", "SECURITY.md"):
            assert f"include {doc}" in text, doc

    def test_built_sdist_omits_dev_trees_and_egg_info_residue(self, tmp_path: Path) -> None:
        """The built sdist carries only the runtime tree, not the dev checkout.

        A src/ layout places egg-info next to the package.  Without an explicit
        MANIFEST prune the residue (PKG-INFO, entry_points, requires.txt)
        lands in the sdist.  setuptools always force-appends
        ``<egg-info>/SOURCES.txt`` after prune — that single file is the
        recorded manifest and is expected.

        The pruned dev trees are asserted against the built archive, not
        against the MANIFEST text: ``test_prunes_dev_trees`` only proves the
        prune lines exist, and ``check_sdist_wheel.py`` compares wheels, which
        never carry these files.  A ``graft``/``global-include`` added later, or
        a prune whose path drifted, would otherwise ship the whole checkout and
        still pass every gate.  Build into tmp_path so this stays
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
        # Nothing from the dev checkout may ride along, at any depth.  Every
        # member is ``<dist>-<version>/<path>`` (the bare archive-root entry
        # carries no path); the first component is the root, so the rest is
        # what MANIFEST.in decided on.  The egg-info trees are skipped: the
        # setuptools-forced SOURCES.txt is expected, and the assertions above
        # pin its directory down to that one file.
        pruned = tuple(f"{tree}/" for tree in _PRUNED_DEV_TREES if not tree.endswith("egg-info"))
        leaked = sorted(n for n in names if "/" in n and n.split("/", 1)[1].startswith(pruned))
        assert leaked == [], f"sdist ships dev-only files: {leaked[:10]}"
        residue = [n for n in names if n.endswith((".pyc", ".pyo")) or "__pycache__/" in n]
        assert residue == [], f"sdist ships bytecode: {residue[:10]}"
        # setuptools force-writes an empty egg_info stub into the sdist after
        # MANIFEST processing (same class as SOURCES.txt) — accept only that
        # harmless form, never a real setuptools config.
        setup_cfgs = [n for n in names if n.endswith(("/setup.cfg", "setup.cfg"))]
        if setup_cfgs:
            assert len(setup_cfgs) == 1, setup_cfgs
            with tarfile.open(sdists[0]) as tf:
                raw = tf.extractfile(setup_cfgs[0])
                assert raw is not None
        assert any(n.endswith("src/rebrew/py.typed") for n in names)
        assert any(n.endswith("src/rebrew/workspace/py.typed") for n in names)
        assert any(n.endswith("src/rebrew/PRINCIPLES.md") for n in names)
        assert any(n.endswith("src/rebrew/AGENTS.md.template") for n in names)
        assert any(n.endswith("/NOTICE") for n in names)
        assert any(n.endswith("/CHANGELOG.md") for n in names)
        assert any(n.endswith("/SECURITY.md") for n in names)
        # Normalization must ensure all files have mode 0644 (no spurious executable bits).
        from tools.normalize_sdist import normalize

        normalize(sdists[0], 0)
        with tarfile.open(sdists[0]) as tf:
            exec_files = [m.name for m in tf.getmembers() if m.isfile() and (m.mode & 0o111)]
        assert exec_files == [], f"normalized sdist has executable files: {exec_files}"

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
            ep_name = next(n for n in names if n.endswith(".dist-info/entry_points.txt"))
            ep_text = zf.read(ep_name).decode()
        skills_root = PKG / "agent-skills"
        missing = [
            f"rebrew/agent-skills/{p.relative_to(skills_root).as_posix()}"
            for p in skills_root.rglob("*")
            if p.is_file()
            and f"rebrew/agent-skills/{p.relative_to(skills_root).as_posix()}" not in names
        ]
        assert missing == [], f"wheel missing skill assets: {missing}"
        assert "rebrew/py.typed" in names
        assert "rebrew/workspace/py.typed" in names
        assert "rebrew/PRINCIPLES.md" in names
        assert "rebrew/AGENTS.md.template" in names
        for script_name in _project()["scripts"]:
            assert f"{script_name} = " in ep_text, f"wheel missing entry point: {script_name}"
        assert "Typing :: Typed" in meta
        assert "Environment :: Console" in meta
        assert "Project-URL: Security," in meta
        assert any(n.endswith("/licenses/LICENSE") for n in names)
        assert any(n.endswith("/licenses/NOTICE") for n in names)
        assert "License-File: NOTICE" in meta
        # Contributor docs: MANIFEST.in recursive-excludes src/rebrew AGENTS.md,
        # [tool.setuptools.exclude-package-data] drops it from the wheel.  Cover
        # every one on disk, not a hand-picked pair, so a new subpackage's copy
        # cannot ride into the runtime artifact.
        shipped_agents = sorted(n for n in names if n.endswith("/AGENTS.md"))
        assert shipped_agents == [], f"wheel ships contributor docs: {shipped_agents}"
        on_disk = {f"rebrew/{p.relative_to(PKG).as_posix()}" for p in PKG.rglob("AGENTS.md")}
        assert on_disk, "expected contributor AGENTS.md files under the package"
        exec_wheel_files = [
            info.filename for info in zf.infolist() if (info.external_attr >> 16) & 0o111
        ]
        assert exec_wheel_files == [], f"wheel has executable files: {exec_wheel_files}"


class TestReleaseCheck:
    """tools/release_check.py — the preflight `make release-check` runs.

    The target is a manual gate (CONTRIBUTING.md), so nothing else exercises
    its logic; a rewrite that silently stopped catching a half-documented
    release would only show up on the one push a release is cut from.
    """

    @staticmethod
    def _check(tmp_path: Path, monkeypatch: Any, changelog: str, version: str = "1.2.3") -> int:
        (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(release_check, "CHANGELOG", tmp_path / "CHANGELOG.md")
        monkeypatch.setattr(release_check, "_package_version", lambda: version)
        monkeypatch.setattr(release_check, "_last_tag", lambda: "v1.2.2")
        return release_check.main()

    def test_clean_release_passes(self, tmp_path: Path, monkeypatch: Any) -> None:
        changelog = "## [Unreleased]\n\n## [1.2.3] - 2026-01-02\n\n### Fixed\n- a thing\n\n## [1.2.2] - 2026-01-01\n"
        assert self._check(tmp_path, monkeypatch, changelog) == 0

    def test_version_not_bumped_fails(self, tmp_path: Path, monkeypatch: Any) -> None:
        changelog = "## [Unreleased]\n\n## [1.2.3] - 2026-01-02\n\n### Fixed\n- a thing\n"
        assert self._check(tmp_path, monkeypatch, changelog, version="1.2.2") == 1

    @pytest.mark.parametrize(
        "changelog",
        [
            pytest.param(
                "## [Unreleased]\n\n### Fixed\n- not moved yet\n\n## [1.2.3] - 2026-01-02\n"
                "\n### Fixed\n- a thing\n",
                id="unreleased-not-empty",
            ),
            pytest.param(
                "## [Unreleased]\n\n## [1.2.3] - 2026-01-02\n\n### Fixed\n\n## [1.2.2] - 2026-01-01\n",
                id="no-entries",
            ),
            pytest.param(
                "## [Unreleased]\n\n## [1.2.3]\n\n### Fixed\n- a thing\n",
                id="undated",
            ),
            pytest.param(
                "## [Unreleased]\n\n## [1.2.3] - 2026-01-02\n\n### Fixed\n- a thing\n"
                "\n## [1.2.3] - 2026-01-03\n\n### Fixed\n- another\n",
                id="split-heading",
            ),
        ],
    )
    def test_changelog_contract_failures(
        self, tmp_path: Path, monkeypatch: Any, changelog: str
    ) -> None:
        assert self._check(tmp_path, monkeypatch, changelog) == 1

    def test_version_compares_numerically_not_lexically(self) -> None:
        assert release_check._is_bumped_past("0.10.0", "v0.9.0")
        assert not release_check._is_bumped_past("0.9.1", "v0.9.1")
        assert not release_check._is_bumped_past("0.9.0", "v0.10.0")
