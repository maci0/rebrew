"""dosbox.py — headless DOSBox runner shared by the 16-bit toolchains.

DOSBox 0.74-3 breaks when the mounted drive sits on tmpfs (e.g. ``/tmp``):
the autoexec shell starts treating commands as ``cd`` and nothing runs.
Sandboxes must therefore live on a non-tmpfs filesystem (the user home when
writable, else a real-disk fallback — see :func:`make_sandbox_dir`); callers
stage their toolchain there before invoking :func:`run_dosbox`.
"""

from __future__ import annotations

import atexit
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
    by ``TestDosboxDriverSync``.
    """
    body = "\n".join(
        [
            "mount c " + str(sandbox),
            "C:",
            "cd \\",
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

    The sandbox is removed when the process exits (same discipline as
    link_sweep's scratch dir) — each 16-bit compile stages compiler trees
    and RTL units into its sandbox, so without the hook one dir leaks into
    ``~/.cache/rebrew/tmp`` per invocation.  Callers that must keep a
    sandbox for post-mortem inspection pass their own *workdir* instead and
    own its lifetime.

    Raises :class:`DosboxError` when no candidate is writable."""
    from rebrew.utils import writable_temp_dir

    try:
        sandbox = writable_temp_dir(prefix)
    except OSError as exc:
        raise DosboxError(str(exc)) from exc
    # ignore_errors=True: a still-mounted sandbox ("Device or resource busy")
    # must not turn interpreter shutdown into a traceback.
    atexit.register(shutil.rmtree, sandbox, True)
    return sandbox


def run_dosbox(
    sandbox: Path,
    autoexec: list[str],
    *,
    timeout: int = 180,
) -> None:
    r"""Run DOSBox headless with *sandbox* mounted as the ``C:`` drive.

    *autoexec* lines execute after ``mount c <sandbox>; C:; cd \`` and
    before ``exit``.  Raises :class:`DosboxError` when dosbox is not on
    PATH, the subprocess fails/times out, or dosbox exits nonzero (the
    compiler never ran, so callers must see why instead of hunting an
    empty output log).
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
        r = subprocess.run(
            ["dosbox", "-conf", str(conf), "-noconsole"],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DosboxError(f"DOSBox invocation failed: {exc}") from exc
    if r.returncode != 0:
        # DOSBox exits 0 even when the DOS compiler fails (errors land in the
        # redirected log), so a nonzero exit means the emulator itself died
        # before running anything.  Surface its output — without this the
        # caller reports "produced no object" with an empty log and no hint
        # that dosbox never started.
        tail = "\n".join((r.stdout + r.stderr).splitlines()[-15:])
        raise DosboxError(
            f"DOSBox exited with code {r.returncode} before completing "
            f"(autoexec: {autoexec!r}); output tail:\n{tail.strip() or '(none)'}"
        )


def read_uppercase(sandbox: Path, name: str) -> str:
    """Read a file DOSBox wrote — it FAT-uppercases names (DCCOUT.TXT)."""
    for candidate in (sandbox / name.upper(), sandbox / name):
        if candidate.exists():
            return candidate.read_text(encoding="utf-8", errors="replace")
    return ""


__all__ = ["DosboxError", "make_sandbox_dir", "read_uppercase", "run_dosbox"]
