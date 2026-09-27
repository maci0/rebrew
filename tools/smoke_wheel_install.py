"""smoke_wheel_install.py — assert the installed wheel is importable and complete.

The package job installs the built wheel into a throwaway venv and then imports
it, so a defect in ``[tool.setuptools] package-data`` shows up here rather than
in a user's install.  ``MANIFEST.in`` and ``package-data`` are separate
mechanisms, and the runtime files this asserts are exactly the ones neither
``import rebrew`` nor the console script reads: a wheel that imports fine but
ships no ``agent-skills/`` tree still runs, and still fails the first
``rebrew skills list``.

Run with the *installed* interpreter, not the project's, so the import
resolves to the wheel's site-packages rather than ``src/``::

    .venv-pkg/bin/python tools/smoke_wheel_install.py

Exits 0 when the installed distribution imports and carries its runtime
files, 1 with the missing path named on stderr otherwise.
"""

from __future__ import annotations

import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

DIST_NAME = "rebrew"

# Runtime files the package must ship, relative to the installed package
# directory. Directories are checked with is_dir(), files with is_file().
RUNTIME_ENTRIES: tuple[tuple[str, str], ...] = (
    ("agent-skills", "dir"),
    ("AGENTS.md.template", "file"),
    ("PRINCIPLES.md", "file"),
)


def check() -> list[str]:
    """Return one message per missing runtime file; empty means the wheel is complete."""
    try:
        installed = version(DIST_NAME)
    except PackageNotFoundError:
        return [f"{DIST_NAME} is not installed in {sys.prefix}"]
    # Imported inside check() so the module imports cleanly under a tree where
    # rebrew is not installed at all (that is the failure this reports).
    import rebrew

    package = Path(rebrew.__file__).resolve().parent
    print(f"{DIST_NAME} {installed} from {package}", file=sys.stderr)
    missing: list[str] = []
    for entry, kind in RUNTIME_ENTRIES:
        path = package / entry
        present = path.is_dir() if kind == "dir" else path.is_file()
        if not present:
            missing.append(f"missing {kind} {path}")
    return missing


def main() -> int:
    missing = check()
    for message in missing:
        print(f"error: {message}", file=sys.stderr)
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
