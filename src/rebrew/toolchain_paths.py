"""toolchain_paths.py — where the rebrew-toolchains build source lives.

The Dockerfiles, wrapper scripts, and the shared base live in the sibling
rebrew-toolchains checkout, overridable with REBREW_TOOLCHAINS_DIR.
"""

from __future__ import annotations

import os
from pathlib import Path

TOOLCHAINS_REPO_URL = "https://github.com/maci0/rebrew-toolchains"


def _repo_root() -> Path:
    """The rebrew checkout root, located by its pyproject.toml marker."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    raise RuntimeError(
        "cannot locate the rebrew checkout root (no pyproject.toml in any parent of this module)"
    )


def toolchains_repo() -> Path:
    """Root of the standalone rebrew-toolchains docker build source.

    Defaults to the sibling checkout (same workspace as this repo),
    overridable via REBREW_TOOLCHAINS_DIR for other layouts.  The external
    repo is the canonical source of the docker-image build files
    (Dockerfiles, the shared base, wrapper scripts); the 16-bit media
    tarballs are expected next to their Dockerfile there."""
    env = os.environ.get("REBREW_TOOLCHAINS_DIR")
    if env:
        return Path(env)
    return _repo_root().parent / "rebrew-toolchains"


REPO_TOOLS = toolchains_repo()


def vendored_path(sub: str) -> Path:
    """A path inside the rebrew-toolchains checkout, resolved at call time."""
    return toolchains_repo() / sub
