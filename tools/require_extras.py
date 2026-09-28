"""require_extras.py — fail with the fix before ``make mypy`` reports phantom errors.

``mypy`` type-checks the ``prove`` and ``similarity`` paths, whose imports only
resolve when those optional distributions are installed.  A bare ``uv sync``
venv therefore produces import-not-found and unused-ignore noise that has
nothing to do with the code under review.  The preflight turns that into one
message naming the missing group and the command that installs it.

This lives in ``tools/`` rather than in a Makefile recipe because a Makefile
recipe is one shell string: a probe written there is an inline interpreter
call, and inline Python has no traceback when it breaks.  One language per
command, one file to read, one line to run.

Usage::

    uv run --frozen --no-sync python tools/require_extras.py [RESEMBL_DIR]

``--no-sync`` matters: the probe must report what is installed, never install
what is missing.  It also matters that the probe never *creates* ``.venv``:
``make doctor`` is documented as read-only, and ``uv run`` builds the venv on
first use, so on a clean clone the Makefile runs this file with the system
python3 instead.  The missing-venv case is reported here rather than inferred
from a probe of the wrong interpreter.  ``RESEMBL_DIR`` (default
``../resembl``) is the sibling path dependency the ``similarity`` group's
message points at; the Makefile passes its resolved absolute path.
"""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

# `uv`'s name for the project virtualenv, which is also the directory
# ``make doctor`` must not create just by reporting on the environment.
VENV_DIRNAME = ".venv"


class _Group(NamedTuple):
    """One optional dependency group mypy needs before it can be trusted."""

    modules: tuple[str, ...]
    label: str
    why: str
    fix: str
    sibling_hint: str = ""


# Checked in order: the `prove` extra first, so a venv missing both is told
# about the larger dependency tree first.
_GROUPS: tuple[_Group, ...] = (
    _Group(
        modules=("angr", "claripy"),
        label="'prove' extra (angr, claripy)",
        why="mypy reports phantom type errors without it (CI's lint job syncs --all-extras)",
        fix="Run 'make setup', or 'uv sync --locked --all-extras --group similarity', then re-run.",
    ),
    _Group(
        modules=("rapidfuzz", "resembl"),
        label="'similarity' group (rapidfuzz, resembl)",
        why=(
            "mypy reports import-not-found in src/rebrew/matcher/scoring.py without it"
            " (CI's lint job syncs --group similarity)"
        ),
        fix="Run 'make setup', or 'uv sync --frozen --all-extras --group similarity', then re-run.",
        sibling_hint=" 'make clone-resembl' fetches the pinned ref.",
    ),
)

_DEFAULT_RESEMBL_DIR = "../resembl"


def _satisfied(modules: Sequence[str]) -> bool:
    """True when every module resolves in this interpreter.

    ``find_spec`` rather than ``import``: mypy only needs the package to
    resolve, and importing angr costs seconds the caller would rather not pay
    on every ``make mypy``.
    """
    return all(importlib.util.find_spec(name) is not None for name in modules)


def _venv_dir() -> Path:
    """The project virtualenv, named the way ``uv`` names it."""
    return Path(__file__).resolve().parent.parent / VENV_DIRNAME


def main(argv: Sequence[str] | None = None) -> int:
    """Check every required module, reporting the first group that is short."""
    args = list(sys.argv[1:] if argv is None else argv)
    resembl_dir = args[0] if args else _DEFAULT_RESEMBL_DIR

    # A venv that does not exist has neither group, whatever interpreter this
    # probe happens to run under.  `make doctor` runs the probe with the
    # system python3 precisely so a clean clone stays untouched, and a system
    # interpreter carrying angr would otherwise report the extra as installed
    # and let `make mypy` run into the phantom errors this exists to name.
    if not _venv_dir().is_dir():
        print(f"ERROR: {VENV_DIRNAME} does not exist, so no optional group is installed.")
        print("mypy reports phantom type errors without the 'prove' extra and")
        print("import-not-found without the 'similarity' group (CI's lint job syncs both).")
        print(_GROUPS[0].fix)
        return 1

    for group in _GROUPS:
        if _satisfied(group.modules):
            continue
        print(f"ERROR: the {group.label} is not installed in .venv.")
        print(f"{group.why}.")
        print(group.fix)
        if group.sibling_hint:
            print(
                f"(make setup also needs the sibling {resembl_dir} checkout;{group.sibling_hint})"
            )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
