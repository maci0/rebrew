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
import threading
from pathlib import Path

from rebrew.errors import RebrewError

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
            # spaces into multiple mount args.  The image
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


class DosboxError(RebrewError, RuntimeError):
    """DOSBox is missing or the run failed."""


#: Sandboxes created by :func:`make_sandbox_dir` (default 16-bit workdirs).
#: One atexit hook sweeps the list — registering ``rmtree`` per call would
#: accumulate one callback (and leave every dir live) until process exit.
_SANDBOXES: list[Path] = []
#: Reuse one live sandbox per *(prefix, thread)* so a long-lived process that
#: compiles many 16-bit TUs sequentially does not accumulate one dir + staged
#: tree per call until atexit, while parallel workers (verify -j N / GA) each
#: get an isolated tree — sharing one sandbox across threads raced on
#: ``.OBJ``/``.EXE`` names and silently mixed compile outputs.
#: Keyed by ``(prefix, thread_ident)`` so dead worker threads (a new
#: ThreadPoolExecutor each ``verify --watch`` pass) can be reaped instead of
#: leaving one orphaned dir per retired thread id until process exit.
#: Guarded by :data:`_SANDBOX_LOCK`: unlocked check-then-create orphaned dirs
#: and raced list/dict mutations.
_SANDBOX_BY_PREFIX: dict[tuple[str, int], Path] = {}
_SANDBOX_ATEXIT_REGISTERED = False
_SANDBOX_LOCK = threading.Lock()


def _reap_dead_thread_sandboxes_locked() -> list[Path]:
    """Drop map entries whose owner thread is gone; return paths to rmtree.

    Caller must hold :data:`_SANDBOX_LOCK`.  Removals happen under the lock;
    filesystem deletes run outside so a slow ``rmtree`` does not stall other
    workers' sandbox lookups.
    """
    live = {t.ident for t in threading.enumerate() if t.ident is not None}
    doomed: list[Path] = []
    for key, path in list(_SANDBOX_BY_PREFIX.items()):
        if key[1] in live:
            continue
        _SANDBOX_BY_PREFIX.pop(key, None)
        try:
            _SANDBOXES.remove(path)
        except ValueError:
            for i, s in enumerate(_SANDBOXES):
                if s == path or s.resolve() == path.resolve():
                    del _SANDBOXES[i]
                    break
        doomed.append(path)
    return doomed


def make_sandbox_dir(prefix: str) -> Path:
    """Create a writable DOSBox sandbox dir, preferring a real-disk,
    container-visible location (see :func:`rebrew.utils.writable_temp_dir`).

    DOSBox breaks on tmpfs mounts and the docker runner mounts the workdir at
    /work, so the user cache dir is preferred when writable; read-only homes
    (sandboxed / CI) fall back to the workspace ``.cache`` and TMPDIR.

    Repeated calls with the same *prefix* on the **same thread** reuse the
    same directory (stale ``.OBJ``/``.EXE`` cleanup in the 16-bit compilers
    already assumes reuse).  Concurrent threads get distinct dirs so parallel
    compiles cannot clobber each other's staged outputs.  Distinct prefixes
    still get distinct dirs.  Sandboxes whose owner thread has exited are
    reaped on the next call (``verify --watch`` rebuilds its pool each pass).
    Every remaining tracked sandbox is removed at process exit;
    :func:`release_sandbox` reclaims one earlier.  Callers that must keep a
    sandbox for post-mortem inspection pass their own *workdir* instead and
    own its lifetime.

    Raises :class:`DosboxError` when no candidate is writable."""
    from rebrew.utils import writable_temp_dir

    # Per-thread key: sequential reuse on one worker, isolation across -j N.
    cache_key = (prefix, threading.get_ident())
    doomed: list[Path] = []
    existing_hit: Path | None = None
    with _SANDBOX_LOCK:
        doomed.extend(_reap_dead_thread_sandboxes_locked())
        existing = _SANDBOX_BY_PREFIX.get(cache_key)
        if existing is not None and existing.is_dir():
            existing_hit = existing
    for path in doomed:
        shutil.rmtree(path, ignore_errors=True)
    if existing_hit is not None:
        return existing_hit

    try:
        sandbox = writable_temp_dir(prefix)
    except OSError as exc:
        raise DosboxError(str(exc)) from exc
    with _SANDBOX_LOCK:
        # Re-check: another worker may have published the same key while
        # we created a dir — keep theirs and drop the orphan.
        existing = _SANDBOX_BY_PREFIX.get(cache_key)
        if existing is not None and existing.is_dir():
            shutil.rmtree(sandbox, ignore_errors=True)
            return existing
        _SANDBOX_BY_PREFIX[cache_key] = sandbox
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
    with _SANDBOX_LOCK:
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
    with _SANDBOX_LOCK:
        dirs = list(_SANDBOXES)
        _SANDBOXES.clear()
        _SANDBOX_BY_PREFIX.clear()
    for path in dirs:
        shutil.rmtree(path, ignore_errors=True)


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
            encoding="utf-8",
            errors="replace",
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
