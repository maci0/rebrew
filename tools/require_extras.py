"""require_extras.py — fail with the fix before the gates report a green that is not.

``mypy`` type-checks the ``prove`` and ``similarity`` paths, whose imports only
resolve when those optional distributions are installed.  A bare ``uv sync``
venv therefore produces import-not-found and unused-ignore noise that has
nothing to do with the code under review.  The same venv makes the prove and
similarity *tests* skip, so the whole-suite gate reports coverage CI does not
have.  The preflight turns both into one message naming the missing group and
the command that installs it.

This lives in ``tools/`` rather than in a Makefile recipe because a Makefile
recipe is one shell string: a probe written there is an inline interpreter
call, and inline Python has no traceback when it breaks.  One language per
command, one file to read, one line to run.

Usage::

    uv run --frozen --no-sync python tools/require_extras.py [--context CONTEXT] [--soft] [RESEMBL_DIR]

``--context`` picks the consequence the message names, because the two gates
fail differently from the same gap: ``mypy`` (the default) reports phantom
type errors, ``test`` reports a green suite that skipped the affected tests.
``--soft`` downgrades the failure to a warning and exits 0, for the
single-file edit-test loop where an unrelated file must stay runnable.

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

CONTEXTS = ("mypy", "test")


class _Group(NamedTuple):
    """One optional dependency group a gate needs before it can be trusted."""

    modules: tuple[str, ...]
    label: str
    why: dict[str, str]
    fix: str
    sibling_hint: str = ""


# Checked in order: the `prove` extra first, so a venv missing both is told
# about the larger dependency tree first.
_GROUPS: tuple[_Group, ...] = (
    _Group(
        modules=("angr", "claripy"),
        label="'prove' extra (angr, claripy)",
        why={
            "mypy": (
                "mypy reports phantom type errors without it (CI's lint job syncs --all-extras)"
            ),
            "test": (
                "the prove tests skip without it, so a green run here is not the"
                " coverage CI's test job runs (CI syncs --all-extras)"
            ),
        },
        fix="Run 'make setup', or 'uv sync --locked --all-extras --group similarity', then re-run.",
    ),
    _Group(
        modules=("rapidfuzz", "resembl"),
        label="'similarity' group (rapidfuzz, resembl)",
        why={
            "mypy": (
                "mypy reports import-not-found in src/rebrew/matcher/scoring.py without it"
                " (CI's lint job syncs --group similarity)"
            ),
            "test": (
                "the similarity tests skip without it, so a green run here is not the"
                " coverage CI's test job runs (CI syncs --group similarity)"
            ),
        },
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


def _parse(argv: Sequence[str]) -> tuple[str, bool, str] | None:
    """Split the flags from the optional path argument, or None if invalid."""
    context = "mypy"
    soft = False
    rest: list[str] = []
    for arg in argv:
        if arg == "--soft":
            soft = True
        elif arg.startswith("--context="):
            context = arg.partition("=")[2]
        elif arg == "--context":
            context = ""
        elif context == "" and not rest:
            context = arg
        else:
            rest.append(arg)
    if context not in CONTEXTS:
        print(f"ERROR: --context must be one of {', '.join(CONTEXTS)} (got '{context}').")
        return None
    return context, soft, rest[0] if rest else _DEFAULT_RESEMBL_DIR


def main(argv: Sequence[str] | None = None) -> int:
    """Check every required module, reporting the first group that is short."""
    parsed = _parse(list(sys.argv[1:] if argv is None else argv))
    if parsed is None:
        return 2
    context, soft, resembl_dir = parsed
    level = "WARNING" if soft else "ERROR"
    rc = 0 if soft else 1

    # A venv that does not exist has neither group, whatever interpreter this
    # probe happens to run under.  `make doctor` runs the probe with the
    # system python3 precisely so a clean clone stays untouched, and a system
    # interpreter carrying angr would otherwise report the extra as installed
    # and let `make mypy` run into the phantom errors this exists to name.
    if not _venv_dir().is_dir():
        print(f"{level}: {VENV_DIRNAME} does not exist, so no optional group is installed.")
        print("mypy reports phantom type errors without the 'prove' extra and")
        print("import-not-found without the 'similarity' group (CI's lint job syncs both).")
        print(_GROUPS[0].fix)
        return rc

    for group in _GROUPS:
        if _satisfied(group.modules):
            continue
        print(f"{level}: the {group.label} is not installed in .venv.")
        print(f"{group.why[context]}.")
        print(group.fix)
        if group.sibling_hint:
            print(
                f"(make setup also needs the sibling {resembl_dir} checkout;{group.sibling_hint})"
            )
        return rc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
