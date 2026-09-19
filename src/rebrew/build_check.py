"""build_check.py — is ``build/`` still the tree CMake generated?

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
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

console = Console()

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

_RECORDED = re.compile(r"Custom (?:flags|options): \S*?(\S+\.obj)_(?:FLAGS|OPTIONS) = (.*)$", re.M)

_OBJ_IN_LINE = re.compile(r"(CMakeFiles/[^ ]*?\.obj)\b")


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


def parse_compile_lines(build_text: str) -> list[tuple[str, str]]:
    """[(object path, compile line)] for every real compile rule.

    The ``/FAs`` listing rules are excluded: they assemble the same file to a
    ``.s`` and are not what produces the linked object.
    """
    out: list[tuple[str, str]] = []
    for line in build_text.splitlines():
        if "cl " not in line.lower() and "cl.exe" not in line.lower():
            continue
        if "/FAs" in line or "cl  /nologo /E " in line:
            continue
        mo = _OBJ_IN_LINE.search(line)
        if mo:
            out.append((mo.group(1), line))
    return out


def check(build_dir: Path = DEFAULT_BUILD_DIR) -> dict[str, Any]:
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

    recorded = parse_recorded(flags_make.read_text(errors="replace"))
    drift: list[dict[str, str]] = []
    checked = 0
    for obj, line in parse_compile_lines(build_make.read_text(errors="replace")):
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

    if drift:
        first = ", ".join(f"{d['obj'].rsplit('/', 1)[-1]}:{d['flag']}" for d in drift[:4])
        return {
            "status": "drift",
            "checked": checked,
            "drift": drift,
            "message": (f"{len(drift)} unrecorded flag token(s) in build.make (first: {first})"),
        }
    return {
        "status": "ok",
        "checked": checked,
        "drift": [],
        "message": f"build.make agrees with flags.make ({checked} object(s) checked)",
    }


app = typer.Typer(add_completion=False, help=__doc__)


@app.callback(invoke_without_command=True)
def main(
    build_dir: Path = typer.Option(
        DEFAULT_BUILD_DIR, "--build-dir", help="CMake build directory to inspect."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit the result as JSON."),
) -> None:
    """Verify build/ still matches what CMake generated.

    Exits non-zero when build.make has been hand-edited, because every
    measurement taken from a drifted tree describes a build no fresh clone can
    reproduce.  Also exits non-zero when there is nothing to check: a mistyped
    ``--build-dir`` must not read as clean, or the command reproduces the very
    silent-pass failure it exists to catch.
    """
    result = check(build_dir)
    if as_json:
        console.print_json(json.dumps(result))
    else:
        style = {"ok": "green", "drift": "red", "not-configured": "yellow"}[result["status"]]
        console.print(f"[{style}]build-check:[/] {result['message']}")
        if result["status"] == "drift":
            console.print(
                "  build.make has been hand-edited.  Restore with:\n"
                "    rm -rf build && cmake -B build -S . "
                "--toolchain cmake/toolchain-<compiler>-docker.cmake "
                "-DCMAKE_BUILD_TYPE=Release -DREBREW_DEBUG_INFO=OFF"
            )
    if result["status"] != "ok":
        raise typer.Exit(1)


__all__ = ["app", "main", "check", "parse_compile_lines", "parse_recorded"]
