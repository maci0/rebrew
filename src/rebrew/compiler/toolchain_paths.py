"""compiler/toolchain_paths.py — where the recompile-toolchains build source lives.

The Dockerfiles, wrapper scripts, and the shared base live in the sibling
recompile-toolchains checkout, overridable with REBREW_TOOLCHAINS_DIR.
"""

from __future__ import annotations

import functools
lazy import os
lazy from pathlib import Path

TOOLCHAINS_REPO_URL = "https://github.com/maci0/recompile-toolchains"

TOOLCHAINS_DIR_ENV = "REBREW_TOOLCHAINS_DIR"
"""Env var overriding the toolchains checkout location.  Unset means the
sibling directory next to this repo."""


def toolchains_repo() -> Path:
    """Root of the standalone toolchains docker build source.

    Defaults to the sibling checkout (same workspace as this repo),
    overridable via REBREW_TOOLCHAINS_DIR for other layouts.  The external
    repo is the canonical source of the docker-image build files
    (Dockerfiles, the shared base, wrapper scripts); the 16-bit media
    tarballs are expected next to their Dockerfile there.

    Never raises: without a locatable checkout (e.g. a ``uv tool install``
    snapshot with no repo on disk) it returns a non-existent sentinel path.
    Callers that merely probe (``.exists()``, ``host_path``) degrade
    gracefully; commands that consume the build source go through
    :func:`rebrew.compiler.toolchain.require_toolchains_repo`, which raises the
    actionable error.
    """
    env = os.environ.get(TOOLCHAINS_DIR_ENV, "").strip()
    if env:
        return Path(env).expanduser()
    return _sibling_toolchains_repo()


@functools.cache
def _sibling_toolchains_repo() -> Path:
    """The checkout next to the one this module was imported from.

    Once per process: the module does not move, and status asks once per
    compiled entry, each time resolving this file and statting its parents.
    """
    for parent in Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").is_file():
            return parent.parent / "recompile-toolchains"
    return Path("__no_recompile_toolchains_checkout__")


def vendored_path(sub: str) -> Path:
    """A path inside the toolchains checkout, resolved at call time."""
    return toolchains_repo() / sub
