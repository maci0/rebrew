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
            # Quote the path: DOSBox would split a sandbox whose path holds
            # spaces into multiple mount args (infra-review F6).  The image
            # wrapper's rebrew_dosbox_run must stay byte-identical
            # (TestDosboxDriverSync).
            f'mount c "{sandbox}"',
            "C:",
            "cd \\",
            *autoexec,
            "exit",
        ]
    )
    return _DOSBOX_CONF_HEADER + body + "\n"


class DosboxError(RuntimeError):
    """DOSBox is missing or the run failed."""


#: Sandboxes created by :func:`make_sandbox_dir` (default 16-bit workdirs).
#: One atexit hook sweeps the list — registering ``rmtree`` per call would
#: accumulate one callback (and leave every dir live) until process exit.
_SANDBOXES: list[Path] = []
#: Reuse one live sandbox per *prefix* so a long-lived process that compiles
#: many 16-bit TUs (msvc16/tc16/delphi16 default workdirs) does not accumulate
#: one dir + staged tree per call until atexit.  Callers that need an isolated
#: tree pass their own *workdir* and own its lifetime.
_SANDBOX_BY_PREFIX: dict[str, Path] = {}
_SANDBOX_ATEXIT_REGISTERED = False


def make_sandbox_dir(prefix: str) -> Path:
    """Create a writable DOSBox sandbox dir, preferring a real-disk,
    container-visible location (see :func:`rebrew.utils.writable_temp_dir`).

    DOSBox breaks on tmpfs mounts and the docker runner mounts the workdir at
    /work, so the user's home is preferred when writable; read-only homes
    (sandboxed / CI) fall back to the workspace ``.cache`` and TMPDIR.

    Repeated calls with the same *prefix* reuse the same directory (stale
    ``.OBJ``/``.EXE`` cleanup in the 16-bit compilers already assumes reuse).
    Distinct prefixes still get distinct dirs.  Every tracked sandbox is
    removed at process exit; :func:`release_sandbox` reclaims one earlier.
    Callers that must keep a sandbox for post-mortem inspection pass their
    own *workdir* instead and own its lifetime.

    Raises :class:`DosboxError` when no candidate is writable."""
    from rebrew.utils import writable_temp_dir

    existing = _SANDBOX_BY_PREFIX.get(prefix)
    if existing is not None and existing.is_dir():
        return existing

    try:
        sandbox = writable_temp_dir(prefix)
    except OSError as exc:
        raise DosboxError(str(exc)) from exc
    _SANDBOX_BY_PREFIX[prefix] = sandbox
    _SANDBOXES.append(sandbox)
    global _SANDBOX_ATEXIT_REGISTERED
    if not _SANDBOX_ATEXIT_REGISTERED:
        # ignore_errors=True: a still-mounted sandbox ("Device or resource busy")
        # must not turn interpreter shutdown into a traceback.
        atexit.register(_cleanup_sandboxes)
        _SANDBOX_ATEXIT_REGISTERED = True
    return sandbox


def release_sandbox(path: Path) -> None:
    """Remove a sandbox previously returned by :func:`make_sandbox_dir`.

    Idempotent: unknown or already-removed paths are ignored.  Prefer this
    over waiting for atexit when the caller no longer needs the staged tree.
    """
    resolved = path.resolve()
    stale_prefixes = [p for p, s in _SANDBOX_BY_PREFIX.items() if s.resolve() == resolved]
    for p in stale_prefixes:
        _SANDBOX_BY_PREFIX.pop(p, None)
    try:
        _SANDBOXES.remove(path)
    except ValueError:
        for i, s in enumerate(_SANDBOXES):
            if s.resolve() == resolved:
                del _SANDBOXES[i]
                break
    shutil.rmtree(path, ignore_errors=True)


def _cleanup_sandboxes() -> None:
    """atexit: remove every sandbox created by :func:`make_sandbox_dir`."""
    _SANDBOX_BY_PREFIX.clear()
    while _SANDBOXES:
        shutil.rmtree(_SANDBOXES.pop(), ignore_errors=True)


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


__all__ = [
    "DosboxError",
    "make_sandbox_dir",
    "read_uppercase",
    "release_sandbox",
    "run_dosbox",
]
