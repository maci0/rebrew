"""dosbox.py — headless DOSBox runner shared by the 16-bit toolchains.

DOSBox 0.74-3 breaks when the mounted drive sits on tmpfs (e.g. ``/tmp``):
the autoexec shell starts treating commands as ``cd`` and nothing runs.
Sandboxes must therefore live on a non-tmpfs filesystem (the user home on
this box); callers stage their toolchain there before invoking
:func:`run_dosbox`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

_DOSBOX_CONF_HEADER = "[sdl]\nfullscreen=false\n\n[cpu]\ncycles=fixed 30000\n\n[autoexec]\n"


class DosboxError(RuntimeError):
    """DOSBox is missing or the run failed."""


def run_dosbox(
    sandbox: Path,
    autoexec: list[str],
    *,
    timeout: int = 180,
) -> None:
    """Run DOSBox headless with *sandbox* mounted as the ``C:`` drive.

    *autoexec* lines execute after ``mount c <sandbox>; C:; cd \\`` and
    before ``exit``.  Raises :class:`DosboxError` when dosbox is not on
    PATH or the subprocess fails/times out.
    """
    if shutil.which("dosbox") is None:
        raise DosboxError(
            "dosbox not found in PATH — 16-bit DOS toolchains must run under "
            "DOSBox (see tools/DELPHI10/README.md)"
        )
    sandbox.mkdir(parents=True, exist_ok=True)
    conf = sandbox / "run.conf"
    body = "\n".join(
        [
            "mount c " + str(sandbox),
            "C:",
            "cd \\",
            *autoexec,
            "exit",
        ]
    )
    conf.write_text(_DOSBOX_CONF_HEADER + body + "\n", encoding="utf-8")

    env = dict(os.environ)
    env.setdefault("SDL_VIDEODRIVER", "dummy")
    try:
        subprocess.run(
            ["dosbox", "-conf", str(conf), "-noconsole"],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DosboxError(f"DOSBox invocation failed: {exc}") from exc


def read_uppercase(sandbox: Path, name: str) -> str:
    """Read a file DOSBox wrote — it FAT-uppercases names (DCCOUT.TXT)."""
    for candidate in (sandbox / name.upper(), sandbox / name):
        if candidate.exists():
            return candidate.read_text(encoding="utf-8", errors="replace")
    return ""


__all__ = ["DosboxError", "read_uppercase", "run_dosbox"]
