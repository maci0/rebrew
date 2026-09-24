"""toolchain_paths.py — where the rebrew-toolchains build source lives.

The Dockerfiles, wrapper scripts, and the shared base live in the sibling
rebrew-toolchains checkout, overridable with REBREW_TOOLCHAINS_DIR.
"""

from __future__ import annotations

import os
from pathlib import Path

TOOLCHAINS_REPO_URL = "https://github.com/maci0/rebrew-toolchains"


def toolchains_repo() -> Path:
    """Root of the standalone rebrew-toolchains docker build source.

    Defaults to the sibling checkout (same workspace as this repo),
    overridable via REBREW_TOOLCHAINS_DIR for other layouts.  The external
    repo is the canonical source of the docker-image build files
    (Dockerfiles, the shared base, wrapper scripts); the 16-bit media
    tarballs are expected next to their Dockerfile there.

    Never raises: without a locatable checkout (e.g. a ``uv tool install``
    snapshot with no repo on disk) it returns a non-existent sentinel path.
    Callers that merely probe (``.exists()``, ``host_path``) degrade
    gracefully; commands that consume the build source go through
    :func:`rebrew.toolchain.require_toolchains_repo`, which raises the
    actionable error.
    """
    env = os.environ.get("REBREW_TOOLCHAINS_DIR", "").strip()
    if env:
        return Path(env)
    for parent in Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").is_file():
            return parent.parent / "rebrew-toolchains"
    return Path("__no_rebrew_toolchains_checkout__")


def vendored_path(sub: str) -> Path:
    """A path inside the rebrew-toolchains checkout, resolved at call time."""
    return toolchains_repo() / sub
