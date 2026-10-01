"""smoke_wheel_install.py — assert the installed wheel is importable and complete.

The package job installs the built wheel into a throwaway venv and then imports
it, so a defect in ``[tool.setuptools] package-data`` shows up here rather than
in a user's install.  ``MANIFEST.in`` and ``package-data`` are separate
mechanisms, and the runtime files this asserts are exactly the ones neither
``import rebrew`` nor the console script reads: a wheel that imports fine but
ships no ``agent-skills/`` tree still runs, and still fails the first
``rebrew skills list``.

Every declared console script is then run as the installer wrote it, because
that shim is the artifact a user invokes and nothing else in the gates
exercises it: ``[project.scripts]`` names a module and an attribute, the
static check imports the module in the *dev* tree, and ``rebrew --help`` covers
the user CLI but not the four external build hooks. A target whose import chain reaches
something the wheel does not carry installs cleanly and fails on first use.

Run with the *installed* interpreter, not the project's, so the import
resolves to the wheel's site-packages rather than ``src/``::

    .venv-pkg/bin/python tools/smoke_wheel_install.py

Exits 0 when the installed distribution imports and carries its runtime
files, 1 with the missing path named on stderr otherwise.
"""

from __future__ import annotations

import subprocess
import sys
from importlib.metadata import EntryPoint, PackageNotFoundError, entry_points, version
from pathlib import Path

DIST_NAME = "rebrew"

# The three CMAKE_C_COMPILER / CMAKE_LINKER / CMAKE_AR wrappers.  CMake runs
# them with a compiler command line, not a CLI one, so `--help` is not a probe
# for them: `rebrew-cmake-cl --help` forwards the flag to cl.exe, which exits
# on the missing source file.  They are probed by the CMake bridge tests
# instead, and the shim still has to exist.
COMPILER_DRIVERS = frozenset({"rebrew-cmake-cl", "rebrew-cmake-link", "rebrew-cmake-lib"})

# A console script that hangs on `--help` is a wedged install, not a slow one.
_SCRIPT_TIMEOUT = 60

# Runtime files the package must ship, relative to the installed package
# directory. Directories are checked with is_dir(), files with is_file().
RUNTIME_ENTRIES: tuple[tuple[str, str], ...] = (
    ("agent-skills", "dir"),
    ("AGENTS.md.template", "file"),
    ("PRINCIPLES.md", "file"),
    # PEP 561 markers. METADATA claims ``Typing :: Typed``; a wheel whose
    # ``**/py.typed`` glob stops matching installs and runs fine, and only the
    # consumer's type-checker notices, as ``rebrew`` silently turning untyped.
    ("py.typed", "file"),
    ("workspace/py.typed", "file"),
)

# Every directory under ``agent-skills/`` is one skill, and a skill is exactly
# its ``SKILL.md``: ``rebrew skills list`` and ``rebrew init`` skip a directory
# without one, so a partial ship has to fail here and not on the user's box.
SKILL_MANIFEST = "SKILL.md"


def missing_skill_manifests(package: Path) -> list[str]:
    """Paths of installed skill directories that carry no ``SKILL.md``."""
    root = package / "agent-skills"
    if not root.is_dir():
        return []
    return [
        str(skill / SKILL_MANIFEST)
        for skill in sorted(root.iterdir())
        if skill.is_dir() and not (skill / SKILL_MANIFEST).is_file()
    ]


def _is_ours(ep: EntryPoint) -> bool:
    """Whether *ep* belongs to the installed rebrew distribution.

    The smoke venv holds the runtime dependency set too, and several of those
    ship console scripts of their own.
    """
    dist = ep.dist
    if dist is None:
        return False
    return dist.metadata["Name"].lower().replace("_", "-") == DIST_NAME


def console_scripts() -> list[str]:
    """Every console script the *installed* distribution declares, sorted."""
    return sorted(ep.name for ep in entry_points(group="console_scripts") if _is_ours(ep))


def unusable_console_scripts(names: list[str] | None = None) -> list[str]:
    """Console scripts the installer did not write, or that do not start.

    A message per offending script.  The script is located next to the running
    interpreter, which is the environment the package job installed the wheel
    into, so this reads the shim the installer produced rather than a checkout
    on ``sys.path``.
    """
    bin_dir = Path(sys.executable).parent
    failures: list[str] = []
    for name in names if names is not None else console_scripts():
        shim = bin_dir / name
        if not shim.is_file():
            failures.append(f"no console script installed at {shim}")
            continue
        if name in COMPILER_DRIVERS:
            continue
        try:
            result = subprocess.run(
                [str(shim), "--help"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_SCRIPT_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            failures.append(f"{name} --help did not exit within {_SCRIPT_TIMEOUT}s")
            continue
        if result.returncode != 0:
            last = (result.stderr or result.stdout).strip().splitlines()
            detail = last[-1] if last else "no output"
            failures.append(f"{name} --help exited {result.returncode}: {detail}")
    return failures


def check(probe_scripts: bool = True) -> list[str]:
    """Return one message per missing runtime file; empty means the wheel is complete.

    ``probe_scripts=False`` narrows the check to the packaged files, for the
    callers that assert one file list at a time.
    """
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
    missing.extend(f"missing file {path}" for path in missing_skill_manifests(package))
    if probe_scripts:
        missing.extend(unusable_console_scripts())
    return missing


def main() -> int:
    missing = check()
    for message in missing:
        print(f"error: {message}", file=sys.stderr)
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
