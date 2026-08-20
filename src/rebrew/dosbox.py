"""dosbox.py — headless DOSBox runner shared by the 16-bit toolchains.

DOSBox 0.74-3 breaks when the mounted drive sits on tmpfs (e.g. ``/tmp``):
the autoexec shell starts treating commands as ``cd`` and nothing runs.
Sandboxes must therefore live on a non-tmpfs filesystem (the user home when
writable, else a real-disk fallback — see :func:`make_sandbox_dir`); callers
stage their toolchain there before invoking :func:`run_dosbox`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

_DOSBOX_CONF_HEADER = "[sdl]\nfullscreen=false\n\n[cpu]\ncycles=fixed 30000\n\n[autoexec]\n"


def _build_dosbox_conf(sandbox: Path, autoexec: list[str]) -> str:
    """Build the DOSBox config for a run.

    Byte-identical to the image-side driver (`wrapper-common.sh`'s
    ``rebrew_dosbox_run`` printf) — the two are the docker-less fallback and
    the containerized path for the same 16-bit compilers, enforced identical
    by ``TestDosboxDriverSync`` (note the double backslash in ``cd \\\\``,
    matching the shell single-quoted printf).
    """
    body = "\n".join(
        [
            "mount c " + str(sandbox),
            "C:",
            "cd \\\\",
            *autoexec,
            "exit",
        ]
    )
    return _DOSBOX_CONF_HEADER + body + "\n"


class DosboxError(RuntimeError):
    """DOSBox is missing or the run failed."""


def make_sandbox_dir(prefix: str) -> Path:
    """Create a writable DOSBox sandbox dir, preferring a real-disk,
    container-visible location (see :func:`rebrew.utils.writable_temp_dir`).

    DOSBox breaks on tmpfs mounts and the docker runner mounts the workdir at
    /work, so the user's home is preferred when writable; read-only homes
    (sandboxed / CI) fall back to the workspace ``.cache`` and TMPDIR.

    Raises :class:`DosboxError` when no candidate is writable."""
    from rebrew.utils import writable_temp_dir

    try:
        return writable_temp_dir(prefix)
    except OSError as exc:
        raise DosboxError(str(exc)) from exc


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
            "DOSBox (see the rebrew-toolchains 16-bit trees)"
        )
    sandbox.mkdir(parents=True, exist_ok=True)
    conf = sandbox / "run.conf"
    conf.write_text(_build_dosbox_conf(sandbox, autoexec), encoding="utf-8")

    env = dict(os.environ)
    # Fully headless: the dummy video driver suppresses the DOSBox window
    # (no X display needed), and the dummy audio driver silences the ALSA
    # device chatter — a compile must never pop a window or touch audio.
    env.setdefault("SDL_VIDEODRIVER", "dummy")
    env.setdefault("SDL_AUDIODRIVER", "dummy")
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


__all__ = ["DosboxError", "make_sandbox_dir", "read_uppercase", "run_dosbox"]
