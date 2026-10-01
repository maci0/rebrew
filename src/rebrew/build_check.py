"""Check whether ``build/`` is still the tree CMake generated.

``build/`` is gitignored in every rebrew project, so no tracked-file check, no
``rebrew lint``, no ``rebrew verify`` and no ``git status`` can see inside it.
That matters because ``build/`` is load-bearing for the reconstruction:

* ``scripts/linktest.sh`` recompiles with the exact command ``build.make``
  records -- that is what makes its deltas comparable to the real build;
* ``scripts/split_link.sh`` links the objects those commands produced;
* ``rebrew postlink`` rewrites the image they link into.

All three therefore treat ``build.make`` as ground truth.  That trust is only
sound while ``build.make`` still says what CMake wrote.  A round that hand-edits
it -- to sweep a per-file flag, a toolchain pin, an ``/O`` option, anything --
changes what every later measurement MEANS while the source tree stays clean and
every other check keeps passing.  Measured on guild-rebrew (round 1051): a
toolchain-pin sweep left the tree reporting 58% residue and a 290,816-byte
deliverable against the correct 286,720 / 8628, with ``cmake --build`` still
nominally succeeding.

The test is self-contained.  CMake regenerates ``flags.make`` alongside
``build.make``, and records each object's custom flags there as

    # Custom flags:   ...<obj>_FLAGS = /O2 /Gd /Oa
    # Custom options: ...<obj>_OPTIONS = /REBREW_TOOLCHAIN:msvc-6.0-sp5-pp

So every codegen flag token in ``build.make``'s compile line must appear in the
corresponding ``Custom`` comment.  A token in one and not the other was added by
hand.  Objects with no ``Custom`` comment have no per-file flags -- they compile
with the global ``C_FLAGS`` -- and are not drift.

**A flag comparison cannot see a wrong object list.**  ``rebrew rename`` rewrites
the source and its cross-references but not the gitignored ``build/``, so
``build.make`` keeps naming the old ``.obj``.  Every flag still agrees, because
the stale objects are simply never looked at: the loop skips any object without a
``Custom`` comment.  Measured on guild-rebrew (round 1080): a rename left
``split_link.sh`` dying at exit 157 while this check reported clean.  So the
check also verifies that every source ``build.make`` compiles still exists, which
is what a rename or delete breaks.  ``build/`` is generator output and cannot be
trusted to describe the source tree it was generated from.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import typer

from rebrew.cli import EXIT_ERROR, EXIT_MISMATCH, console, json_print

log = logging.getLogger(__name__)

#: Where CMake puts the generated build system, relative to the project root.
DEFAULT_BUILD_DIR = Path("build")

#: Tokens CMake emits for every object that are not codegen flags and that never
#: appear in the Custom comments.
BOILERPLATE = frozenset({"/nologo", "/c", "/W3"})

#: Output/layout switch prefixes (``/Fo``, ``/Fd``, ``/Yu``, ``/Zi`` ...) --
#: paths and debug-info plumbing rather than codegen.
PREFIX_SKIP = ("/F", "/Y", "/Z")

#: An MSVC flag is a slash followed by an UPPERCASE letter.  An absolute POSIX
#: source path is a slash followed by lowercase, so this separates the two
#: without enumerating path prefixes.
_FLAG = re.compile(r"^/[A-Z]")

# `[^\S\n]*$`, not `$`: `re.M` anchors before the `\n`, so on a CRLF
# `flags.make` a bare `$` leaves the `\r` as the last flag token while
# `parse_compile_lines` reads `build.make` through `splitlines()`, which strips
# it.  The two halves would then disagree on a token neither side actually
# holds.  The class is horizontal whitespace only, so the match cannot run past
# the end of its own line.
_RECORDED = re.compile(
    r"Custom (?:flags|options): \S*?(\S+\.obj)_(?:FLAGS|OPTIONS) = (.*?)[^\S\n]*$",
    re.M,
)

_OBJ_IN_LINE = re.compile(r"(CMakeFiles/[^ ]*?\.obj)\b")

#: The source CMake compiles: the path following ``-c``.  Taking a bare ``*.c``
#: token instead also matches the ``/Fo....c.obj`` output path and the dependency
#: files, which is how the first version of this check reported 398 missing
#: sources on a healthy tree.
_SOURCE_IN_LINE = re.compile(r"(?:^|\s)-c\s+(\S+\.(?:c|cc|cpp|cxx))(?:\s|$)")


def parse_recorded(flags_text: str) -> dict[str, set[str]]:
    """Map each object to the flag tokens CMake recorded for it.

    ``re.M`` is required: without it ``$`` anchors to end-of-string, so on a
    ``flags.make`` with hundreds of ``Custom`` comments this matches nothing and
    the caller reports "clean" while comparing zero objects.  That mistake was
    made once already; the summary reports the compared count so a zero is
    visible.
    """
    recorded: dict[str, set[str]] = {}
    for match in _RECORDED.finditer(flags_text):
        recorded.setdefault(match.group(1), set()).update(match.group(2).split())
    return recorded


def _real_compile_lines(build_text: str) -> Iterator[str]:
    """Yield the build lines that invoke the compiler to produce an object.

    The ``/FAs`` listing rules are excluded: they assemble the same file to a
    ``.s`` and are not what produces the linked object.
    """
    for line in build_text.splitlines():
        if "cl " not in line.lower() and "cl.exe" not in line.lower():
            continue
        if "/FAs" in line or "cl  /nologo /E " in line:
            continue
        yield line


def parse_compile_lines(build_text: str) -> list[tuple[str, str]]:
    """[(object path, compile line)] for every real compile rule."""
    out: list[tuple[str, str]] = []
    for line in _real_compile_lines(build_text):
        mo = _OBJ_IN_LINE.search(line)
        if mo:
            out.append((mo.group(1), line))
    return out


def per_file_pin(source_path: Path, build_dir: Path = DEFAULT_BUILD_DIR) -> tuple[str | None, str]:
    """The toolchain + flags CMake pins for one source file.

    Reads the generated ``flags.make`` ``Custom options`` / ``Custom flags``
    comments.  ``/REBREW_TOOLCHAIN:...`` is the per-file toolchain pin, the
    rest is the per-file ``COMPILE_FLAGS`` — exactly what the real link
    compiles the file with, so ``test``/``verify`` can honour it when the
    metadata is silent.

    Returns ``(toolchain, flags)`` — both ``None``/``""`` when the file is not
    pinned (no build tree, or no Custom comment for it).

    Matches the object record by stem: CMake spells the object
    ``<dir>.dir/<stem>.obj`` in the ``Custom`` comment and the build tree
    stores it under the same ``<stem>.obj`` basename.  This is a best-effort
    surface for a single-file pin; the authoritative whole-tree check is
    :func:`check`.
    """
    flags_make: Path | None = None
    cm = build_dir / "CMakeFiles"
    try:
        dirs = sorted(cm.iterdir())
    except FileNotFoundError:
        return None, ""
    except OSError as exc:
        # An unreadable build tree is not an absent one: returning "no pin"
        # compiles the file with the metadata flags instead of the pinned
        # ones, and the byte diff is then blamed on the source.
        log.warning("cannot list %s, per-file pin unavailable: %s", cm, exc)
        return None, ""
    for td in dirs:
        if td.is_dir() and (td / "flags.make").is_file():
            flags_make = td / "flags.make"
            break
    if flags_make is None:
        return None, ""
    recorded = parse_recorded(flags_make.read_text(encoding="utf-8", errors="replace"))
    # The recorded key embeds the source's relative path, e.g.
    # ``CMakeFiles/dir/src/a/one.c.obj`` for ``src/a/one.c``.  Match the object
    # whose basename is ``<source-name>.obj`` (source NAME, not stem, because
    # ``one.c`` -> ``one.c.obj``).
    want = source_path.name + ".obj"
    for obj, tokens in recorded.items():
        if Path(obj).name != want:
            continue
        toolchain = next(
            (tok.split(":", 1)[1] for tok in tokens if tok.startswith("/REBREW_TOOLCHAIN:")),
            None,
        )
        flags = " ".join(
            t for t in tokens if not t.startswith(("/REBREW_TOOLCHAIN", "/F", "/Y", "/Z"))
        )
        return toolchain, flags
    return None, ""


def parse_sources(build_text: str) -> list[str]:
    """Every source path a compile rule names, in first-seen order.

    Paths are returned as written: CMake spells them absolute for the sources in
    this project, and the existence test resolves a relative one against the
    project root.
    """
    out: list[str] = []
    seen: set[str] = set()
    for line in _real_compile_lines(build_text):
        for match in _SOURCE_IN_LINE.finditer(line):
            src = match.group(1)
            if src not in seen:
                seen.add(src)
                out.append(src)
    return out


def check(
    build_dir: Path = DEFAULT_BUILD_DIR,
    project_root: Path | None = None,
    *,
    objects: bool = False,
) -> dict[str, Any]:
    """Return ``{"status", "checked", "drift", "message"}``.

    ``status`` is one of ``ok``, ``drift`` or ``not-configured``.  The last is a
    distinct state and callers must not read it as success: a mistyped
    ``--build-dir`` yields it, and treating that as clean would reproduce exactly
    the silent-pass failure this command exists to catch.
    """
    bm_dir = build_dir / "CMakeFiles" / "server_dll.dir"
    build_make, flags_make = bm_dir / "build.make", bm_dir / "flags.make"
    if not build_make.exists() or not flags_make.exists():
        missing = build_make if not build_make.exists() else flags_make
        return {
            "status": "not-configured",
            "checked": 0,
            "drift": [],
            "message": f"{missing} does not exist -- {build_dir} is not configured",
        }

    # CMake writes UTF-8; never decode with the platform default (cp1252 on
    # Windows, etc.) — a non-ASCII path in build.make would mojibake or raise.
    build_text = build_make.read_text(encoding="utf-8", errors="replace")
    root = project_root if project_root is not None else build_dir.parent

    # A source the build compiles but the tree no longer has means the build
    # system describes a tree that does not exist -- a rename or delete since the
    # last configure.  Checked before the flags, because it makes every flag
    # comparison below meaningless: the stale objects are not in `recorded` and
    # so are skipped rather than flagged.
    def _resolves(src: str) -> bool:
        path = Path(src)
        return (path if path.is_absolute() else root / path).exists()

    absent = [s for s in parse_sources(build_text) if not _resolves(s)]
    if absent:
        first = ", ".join(absent[:4])
        return {
            "status": "drift",
            "checked": 0,
            "drift": [{"obj": s, "flag": "MISSING SOURCE"} for s in absent],
            "message": (
                f"{len(absent)} source(s) in build.make no longer exist (first: {first}) -- "
                f"{build_dir} is stale; re-run the configure step"
            ),
        }

    recorded = parse_recorded(flags_make.read_text(encoding="utf-8", errors="replace"))
    drift: list[dict[str, str]] = []
    checked = 0
    compile_lines = parse_compile_lines(build_text)
    for obj, line in compile_lines:
        # No Custom comment means no per-file flags: the object compiles with the
        # global C_FLAGS.  That is the normal case for most of a tree, and
        # comparing it would report every global flag as drift.
        if obj not in recorded:
            continue
        checked += 1
        known = recorded[obj]
        for token in line.split():
            if not _FLAG.match(token) or token in BOILERPLATE:
                continue
            if token.startswith(PREFIX_SKIP):
                continue
            if token not in known:
                drift.append({"obj": obj, "flag": token})

    if checked == 0 and compile_lines and not drift:
        # Every object lost its Custom comment (a CMake format change, a
        # hand-edited flags.make), so nothing was compared.  Reporting "ok"
        # here is the silent pass this command exists to prevent.
        first = ", ".join(sorted({o for o, _ in compile_lines})[:4])
        return {
            "status": "not-configured",
            "checked": 0,
            "drift": [],
            "message": (
                f"no object in build.make has a Custom flags comment in "
                f"{flags_make} (first: {first}) -- re-run the configure step"
            ),
        }

    if drift:
        first = ", ".join(f"{d['obj'].rsplit('/', 1)[-1]}:{d['flag']}" for d in drift[:4])
        return {
            "status": "drift",
            "checked": checked,
            "drift": drift,
            "message": (f"{len(drift)} unrecorded flag token(s) in build.make (first: {first})"),
        }
    if objects and compile_lines:
        if shutil.which("make") is None:
            return {
                "status": "not-configured",
                "checked": checked,
                "drift": [],
                "message": "object freshness requires Make on PATH",
            }
        # Make owns the dependency graph, including headers; source-only mtime
        # checks miss stale objects after a shared header changes. -q builds nothing.
        # make echoes build.make paths in the host encoding; decode losslessly so a
        # non-UTF-8 byte under LC_ALL=C cannot raise UnicodeDecodeError.
        result = subprocess.run(
            [
                "make",
                "-q",
                "-f",
                str(build_make.resolve()),
                *dict.fromkeys(obj for obj, _ in compile_lines),
            ],
            cwd=build_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="surrogateescape",
            check=False,
        )
        if result.returncode:
            return {
                "status": "drift" if result.returncode == 1 else "not-configured",
                "checked": checked,
                "drift": [{"obj": str(build_dir), "flag": "STALE OBJECTS"}]
                if result.returncode == 1
                else [],
                "message": "native objects need rebuilding (including header dependencies)"
                if result.returncode == 1
                else f"object freshness check failed: {result.stderr.strip()}",
            }
    return {
        "status": "ok",
        "checked": checked,
        "drift": [],
        "message": f"build.make agrees with flags.make ({checked} object(s) checked)",
    }


#: The module docstring is design notes, not help: it is RST, and Rich would
#: render its double backticks and emphasis markers literally.  A one-line help
#: plus an ``Examples:`` epilog is what the rest of the CLI shows.
app = typer.Typer(
    add_completion=False,
    help="Check that build/ still holds what CMake generated (hand-edit drift).",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew build-check · · · · · · · Inspect the default build/ tree\n\n"
        "  rebrew build-check --json · · · · Machine-readable result\n\n"
        "  rebrew build-check --build-dir out/x64 · Check a non-default tree\n\n"
        "[bold]Exit codes:[/bold] 0 in sync · 1 drift · 2 nothing to check "
        "(missing or mistyped --build-dir)\n\n"
        "[dim]build/ is gitignored, so no tracked-file check can see a hand-edited "
        "build.make. Drift means every later measurement describes a build no fresh "
        "clone can reproduce.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    build_dir: Path = typer.Option(
        DEFAULT_BUILD_DIR, "--build-dir", help="CMake build directory to inspect."
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    objects: bool = typer.Option(
        False,
        "--objects",
        help="Also ask Make whether native objects and header dependencies are current.",
    ),
) -> None:
    """Verify build/ still matches what CMake generated.

    Exits non-zero when build.make has been hand-edited, because every
    measurement taken from a drifted tree describes a build no fresh clone can
    reproduce.  Also exits non-zero when there is nothing to check: a mistyped
    ``--build-dir`` must not read as clean, or the command reproduces the very
    silent-pass failure it exists to catch.
    """
    result = check(build_dir, objects=objects)
    if json_output:
        json_print(result)
    else:
        style = {"ok": "green", "drift": "red", "not-configured": "yellow"}[result["status"]]
        console.print(f"[{style}]build-check:[/] {result['message']}")
        if (
            result["status"] == "drift"
            and objects
            and any(row["flag"] == "STALE OBJECTS" for row in result["drift"])
        ):
            console.print("  Rebuild the native object targets before comparing the linked image.")
        elif result["status"] == "drift":
            console.print(
                "  build.make has been hand-edited.  Restore with:\n"
                "    rm -rf build && cmake -B build -S . "
                "--toolchain cmake/toolchain-<compiler>-docker.cmake "
                "-DCMAKE_BUILD_TYPE=Release -DREBREW_DEBUG_INFO=OFF"
            )
    if result["status"] == "drift":
        raise typer.Exit(code=EXIT_MISMATCH)
    if result["status"] != "ok":
        raise typer.Exit(code=EXIT_ERROR)


__all__ = [
    "app",
    "main",
    "main_entry",
    "check",
    "parse_compile_lines",
    "parse_recorded",
    "parse_sources",
    "per_file_pin",
]


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
