"""release_check.py — the version / changelog / tag contract a release must meet.

Manual by design (CONTRIBUTING.md "Cut the release in this order"): a version
that is bumped only on a release commit means wiring this into CI would fail
every other push.  ``make release-check`` runs it before the tag is cut, so a
release whose ``__version__`` is not past the last tag, whose working tree is
dirty, whose changelog notes are split across ``[Unreleased]`` and
``[<version>]``, or whose bump is a patch while the dated section carries a
``**Breaking:**`` entry, fails with a named reason instead of shipping
half-documented.

The checks live here rather than in the Makefile recipe because the version
comes out of the package: a shell recipe had to read it with ``python -c``,
and the changelog scan that followed was awk and grep in the same string.  One
language per command, and a failure names a file and a line.

Usage::

    python tools/release_check.py

Exits 0 when the tree is ready to tag, 1 with every problem it found otherwise.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

CHANGELOG = Path("CHANGELOG.md")

_NO_TAG = "v0.0.0"


def _package_version() -> str:
    """Return ``rebrew.__version__`` from the working tree."""
    from rebrew import __version__

    return __version__


def _last_tag() -> str:
    """Return the most recent tag reachable from HEAD, or v0.0.0 without one."""
    result = subprocess.run(
        ["git", "describe", "--tags", "--abbrev=0"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return result.stdout.strip() or _NO_TAG


def _is_bumped_past(version: str, last: str) -> bool:
    """True when ``version`` sorts strictly after the last tag's version.

    Compares numeric release segments, not strings: 0.10.0 must outrank 0.9.0.
    A segment that is not a number (a pre-release suffix, say) sorts as 0 and
    loses, which fails the gate rather than passing a malformed version.
    """
    last_parts = _release_segments(last.removeprefix("v"))
    new_parts = _release_segments(version)
    return tuple(new_parts) > tuple(last_parts)


def _release_segments(version: str) -> list[int]:
    """Return the leading numeric segments of a version string."""
    segments: list[int] = []
    for part in version.split("."):
        if not part.isdigit():
            break
        segments.append(int(part))
    return segments


def _changelog() -> str:
    return CHANGELOG.read_text(encoding="utf-8")


def _section_body(text: str, heading: re.Pattern[str]) -> list[str]:
    """Return the non-blank lines under the first heading ``heading`` matches.

    The block ends at the next ``## `` heading, so a section is read the way a
    reader reads it: until the next section, not to the end of the file.
    """
    body: list[str] = []
    inside = False
    for line in text.splitlines():
        if heading.match(line):
            inside = True
            continue
        if not inside:
            continue
        if line.startswith("## "):
            break
        if line.strip():
            body.append(line)
    return body


def _problems(version: str, text: str) -> list[str]:
    """Return every CHANGELOG contract the current version breaks."""
    problems: list[str] = []
    section = re.compile(rf"^## \[{re.escape(version)}\] - ")
    dated = re.compile(rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$")
    headings = [line for line in text.splitlines() if section.match(line)]
    if len(headings) != 1:
        problems.append(
            f"CHANGELOG.md has {len(headings)} '## [{version}] - ' headings,"
            " not 1 (merge the split notes)"
        )
    if not any(dated.match(line) for line in headings):
        problems.append(
            f"CHANGELOG.md has no dated [{version}] - YYYY-MM-DD section"
            " (date the [Unreleased] block)"
        )

    unreleased = _section_body(text, re.compile(r"^## \[Unreleased\]$"))
    if unreleased:
        problems.append(
            f"CHANGELOG.md [Unreleased] still has {len(unreleased)} entries;"
            f" move them into [{version}]"
        )

    if not [line for line in _section_body(text, section) if line.startswith("- ")]:
        problems.append(f"CHANGELOG.md [{version}] section has no entries")

    return problems


def _bump_problems(version: str, last: str, text: str) -> list[str]:
    """Return every reason the bump itself is the wrong level for the notes.

    The tree-level gates in ``tests/test_packaging.py`` catch a bad bump long
    after the fact; this is the same rule at the moment the tag is cut, where
    it can still be fixed by editing the version.
    """
    problems: list[str] = []
    if not _is_bumped_past(version, last):
        # The version still names the last tag, so its dated section is a
        # shipped release; the not-bumped problem already reports that, and
        # scoring it here would blame a release for a bump that has not
        # happened yet.
        return problems
    segment = re.compile(r"^## \[" + re.escape(version) + r"\] - ")
    breaking = [line for line in _section_body(text, segment) if line.startswith("- **Breaking:**")]
    if not breaking:
        return problems
    old, new = _release_segments(last.removeprefix("v")), _release_segments(version)
    if new[:2] == old[:2]:
        problems.append(
            f"CHANGELOG.md [{version}] carries {len(breaking)} '**Breaking:**' entries, so "
            f"the {last} -> {version} bump must not be a patch (CONTRIBUTING.md: a break "
            f"ships in a minor, where a '~=' pin does not take it)"
        )
    return problems


def main() -> int:
    """Print every reason the tree is not ready to tag, or confirm it is."""
    version = _package_version()
    last = _last_tag()
    problems: list[str] = []

    if not _is_bumped_past(version, last):
        problems.append(f"__version__ ({version}) not bumped past last tag ({last})")
    dirty = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    ).stdout.strip()
    if dirty:
        problems.append("working tree not clean (commit first)")

    problems += _problems(version, _changelog())
    problems += _bump_problems(version, last, _changelog())

    if problems:
        for problem in problems:
            print(f"ERROR: {problem}")
        return 1
    print(f"release preflight OK: version {version} (last tag {last})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
