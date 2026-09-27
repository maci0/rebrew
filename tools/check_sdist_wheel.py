"""check_sdist_wheel.py — prove the sdist carries everything the wheel ships.

The sdist is what ``pip install rebrew==X`` compiles when no wheel matches, and
its file list comes from ``MANIFEST.in`` plus setuptools' prune/exclude rules —
a different source of truth from the wheel's package-data list.  A prune rule
that removes a runtime file (``src/rebrew/AGENTS.md`` is already
``recursive-exclude``d, and ``PRINCIPLES.md`` / ``AGENTS.md.template`` /
``agent-skills/`` are what the package job asserts in the installed wheel) ships
a wheel that works and an sdist that installs broken.

``make build`` also rewrites both archives after the build
(``tools/normalize_sdist.py`` replaces the sdist's tar and gzip metadata), so
the shipped sdist is not the byte stream setuptools produced either.

Usage::

    python tools/check_sdist_wheel.py dist/rebrew-1.2.3-py3-none-any.whl \\
        .sdist-check/rebrew-1.2.3-py3-none-any.whl

Build the second wheel *from the sdist* (see the ``sdist-check`` Makefile
target) so the comparison covers the manifest, the prune rules, and the
post-build rewrite.  Both member names and member bytes are compared: the two
wheels differ in recorded timestamps, not in content, so a member whose payload
drifted between the checkout and the sdist is a real difference and must fail.
"""

from __future__ import annotations

import hashlib
import sys
import zipfile
from pathlib import Path

# Directory entries setuptools emits inside a wheel. They carry no payload and
# appear or vanish with the build path, so they are not part of the contract.
_IGNORED_DIR_SUFFIX = "/"


def wheel_members(path: Path) -> set[str]:
    """Names of the payload files in *path*, ignoring directory entries."""
    return set(wheel_digests(path))


def wheel_digests(path: Path) -> dict[str, str]:
    """sha256 of every payload file in *path*, keyed by member name.

    Directory entries carry no payload and appear or vanish with the build
    path, so they are excluded here as well as from :func:`wheel_members`.
    """
    if not path.is_file():
        raise FileNotFoundError(f"no such wheel: {path}")
    with zipfile.ZipFile(path) as zf:
        return {
            info.filename: hashlib.sha256(zf.read(info.filename)).hexdigest()
            for info in zf.infolist()
            if not info.filename.endswith(_IGNORED_DIR_SUFFIX)
        }


def diff_members(shipped: set[str], from_sdist: set[str]) -> list[str]:
    """Report the symmetric difference, worst-first: missing, then extra."""
    missing = sorted(shipped - from_sdist)
    extra = sorted(from_sdist - shipped)
    return [f"missing from the sdist-built wheel: {n}" for n in missing] + [
        f"only in the sdist-built wheel: {n}" for n in extra
    ]


def diff_contents(shipped: dict[str, str], from_sdist: dict[str, str]) -> list[str]:
    """Report members present in both wheels whose bytes differ."""
    return [
        f"content differs: {name} (shipped sha256 {shipped[name][:12]}, "
        f"sdist-built sha256 {from_sdist[name][:12]})"
        for name in sorted(shipped.keys() & from_sdist.keys())
        if shipped[name] != from_sdist[name]
    ]


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "usage: check_sdist_wheel.py <shipped-wheel> <wheel-built-from-sdist>",
            file=sys.stderr,
        )
        return 2
    shipped_path, sdist_path = Path(argv[1]), Path(argv[2])
    shipped = wheel_digests(shipped_path)
    from_sdist = wheel_digests(sdist_path)
    problems = diff_members(set(shipped), set(from_sdist)) + diff_contents(shipped, from_sdist)
    if problems:
        print(
            f"the sdist does not reproduce the wheel ({len(shipped)} files in "
            f"{shipped_path.name}, {len(from_sdist)} in {sdist_path.name}):",
            file=sys.stderr,
        )
        for line in problems:
            print(f"  {line}", file=sys.stderr)
        print(
            "Fix the MANIFEST.in prune/exclude rules (or package-data) so a source "
            "install ships the same runtime files as the wheel.",
            file=sys.stderr,
        )
        return 1
    print(f"sdist reproduces the wheel: {len(shipped)} files, byte-identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
