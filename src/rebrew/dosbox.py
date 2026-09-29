"""dosbox.py — headless DOSBox runner shared by the 16-bit toolchains.

DOSBox 0.74-3 breaks when the mounted drive sits on tmpfs (e.g. ``/tmp``):
the autoexec shell starts treating commands as ``cd`` and nothing runs.
Sandboxes must therefore live on a non-tmpfs filesystem (the user home when
writable, else a real-disk fallback — see :func:`make_sandbox_dir`); callers
stage their toolchain there before invoking :func:`run_dosbox`.
"""

from __future__ import annotations

import atexit
import itertools
import os
import shutil
import subprocess
import threading
from pathlib import Path

from rebrew.errors import RebrewError
from rebrew.utils import run_process_group

_DOSBOX_CONF_HEADER = "[sdl]\nfullscreen=false\n\n[cpu]\ncycles=fixed 30000\n\n[autoexec]\n"


def _build_dosbox_conf(sandbox: Path, autoexec: list[str]) -> str:
    """Build the DOSBox config for a run.

    Byte-identical to the image-side driver (`wrapper-common.sh`'s
    ``rebrew_dosbox_run`` printf) — the two are the docker-less fallback and
    the containerized path for the same 16-bit compilers, enforced identical
    by ``TestDosboxDriverSync``.
    """
    # The conf is a line-oriented command file and DOSBox exposes the host root
    # as ``Z:``, so a CR or LF in a caller-supplied line would add conf
    # commands.  Refuse rather than sanitize, matching the sandbox-path refusal
    # in make_sandbox_dir.
    for line in autoexec:
        if any(ch in line for ch in "\r\n"):
            raise DosboxError(f"autoexec line has unsafe characters: {line[:40]!r}")
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
#: The per-thread half of the key is a token from :data:`_SANDBOX_TOKENS`, not
#: ``threading.get_ident()``: CPython recycles an ident once its thread dies, so
#: a new worker inheriting a retired id also inherited its staged tree — the
#: exact cross-run output mixing the per-thread key exists to prevent.  Tokens
#: are never reused, so dead workers (a new ThreadPoolExecutor each
#: ``verify --watch`` pass) are reaped instead of leaving one orphaned dir per
#: retired thread until process exit.
#: Guarded by :data:`_SANDBOX_LOCK`: unlocked check-then-create orphaned dirs
#: and raced list/dict mutations.
_SANDBOX_BY_PREFIX: dict[tuple[str, int], Path] = {}
_SANDBOX_TOKENS = threading.local()
_SANDBOX_TOKEN_SEQ = itertools.count(1)
#: sandbox token -> the thread that owns it, for the liveness check in
#: :func:`_reap_dead_thread_sandboxes_locked`.  Guarded by
#: :data:`_SANDBOX_LOCK`.
_SANDBOX_OWNER: dict[int, threading.Thread] = {}
_SANDBOX_ATEXIT_REGISTERED = False
_SANDBOX_LOCK = threading.Lock()


def _sandbox_token() -> int:
    """The calling thread's sandbox key, minted once and never reused.

    Re-registered when the reaper has forgotten it, so a live thread that
    outlives a reap still owns its sandbox.
    """
    token = getattr(_SANDBOX_TOKENS, "token", None)
    with _SANDBOX_LOCK:
        if token is None or token not in _SANDBOX_OWNER:
            token = next(_SANDBOX_TOKEN_SEQ)
            _SANDBOX_TOKENS.token = token
            _SANDBOX_OWNER[token] = threading.current_thread()
    return token


def _untrack_sandbox(path: Path) -> None:
    """Drop *path* from :data:`_SANDBOXES`, matching on resolved form.

    Caller must hold :data:`_SANDBOX_LOCK`.  A path can be handed back in a
    non-normalized spelling (``./sandbox``), which ``list.remove`` misses, so
    fall back to a linear scan by resolved path.
    """
    try:
        _SANDBOXES.remove(path)
    except ValueError:
        resolved = path.resolve()
        for i, s in enumerate(_SANDBOXES):
            if s == path or s.resolve() == resolved:
                del _SANDBOXES[i]
                break


def _reap_dead_thread_sandboxes_locked() -> list[Path]:
    """Drop map entries whose owner thread is gone; return paths to rmtree.

    Caller must hold :data:`_SANDBOX_LOCK`.  Removals happen under the lock;
    filesystem deletes run outside so a slow ``rmtree`` does not stall other
    workers' sandbox lookups.

    The owner sweep covers tokens that never published a sandbox as well: a
    worker whose :func:`writable_temp_dir` call raised still holds a token and
    a ``Thread`` object, and the sandbox pass alone would never see it.  A new
    pool per ``verify --watch`` pass retires those workers, so without this
    one entry (and its thread object) accumulated per failed spawn.
    """
    doomed: list[Path] = []
    for key, path in list(_SANDBOX_BY_PREFIX.items()):
        owner = _SANDBOX_OWNER.get(key[1])
        if owner is not None and owner.is_alive():
            continue
        _SANDBOX_BY_PREFIX.pop(key, None)
        _SANDBOX_OWNER.pop(key[1], None)
        _untrack_sandbox(path)
        doomed.append(path)
    for token, owner in list(_SANDBOX_OWNER.items()):
        if not owner.is_alive():
            del _SANDBOX_OWNER[token]
    return doomed


def make_sandbox_dir(prefix: str) -> Path:
    """Create a writable DOSBox sandbox dir, preferring a real-disk,
    container-visible location (see :func:`rebrew.temp_dirs.writable_temp_dir`).

    DOSBox breaks on tmpfs mounts and the docker runner mounts the workdir at
    /work, so the user cache dir is preferred when writable; read-only homes
    (sandboxed / CI) fall back to the workspace ``.cache`` and TMPDIR.  A
    candidate that turns out to be tmpfs is rejected outright
    (``require_real_disk=True``) rather than preferred, since XDG_CACHE_HOME
    and the system temp dir are both commonly tmpfs.

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
    from rebrew.temp_dirs import writable_temp_dir

    # Per-thread key: sequential reuse on one worker, isolation across -j N.
    cache_key = (prefix, _sandbox_token())
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
        sandbox = writable_temp_dir(prefix, require_real_disk=True)
    except OSError as exc:
        raise DosboxError(str(exc)) from exc
    # The path is spliced into the DOSBox conf as ``mount c "<sandbox>"``, and
    # the conf is a line-oriented command file: a quote or newline in the base
    # directory (it comes from TMPDIR / XDG_CACHE_HOME) would end the mount
    # argument and add conf commands.  Refuse rather than sanitize, matching
    # the project-dir refusal in decompiler.py.
    if any(ch in str(sandbox) for ch in '"\r\n'):
        shutil.rmtree(sandbox, ignore_errors=True)
        raise DosboxError(
            f"temp base directory {str(sandbox)!r} has unsafe characters for a DOSBox conf"
        )
    with _SANDBOX_LOCK:
        # Re-check: another worker may have published the same key while
        # we created a dir — keep theirs and drop the orphan.  The orphan
        # delete happens after the lock is dropped, like the reaper's.
        existing = _SANDBOX_BY_PREFIX.get(cache_key)
        if existing is None or not existing.is_dir():
            _SANDBOX_BY_PREFIX[cache_key] = sandbox
            _SANDBOXES.append(sandbox)
            global _SANDBOX_ATEXIT_REGISTERED
            if not _SANDBOX_ATEXIT_REGISTERED:
                # ignore_errors=True: a still-mounted sandbox ("Device or resource busy")
                # must not turn interpreter shutdown into a traceback.
                atexit.register(_cleanup_sandboxes)
                _SANDBOX_ATEXIT_REGISTERED = True
            return sandbox
    shutil.rmtree(sandbox, ignore_errors=True)
    return existing


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
        _untrack_sandbox(path)
    shutil.rmtree(path, ignore_errors=True)


def _cleanup_sandboxes() -> None:
    """atexit: remove every sandbox created by :func:`make_sandbox_dir`."""
    with _SANDBOX_LOCK:
        dirs = list(_SANDBOXES)
        _SANDBOXES.clear()
        _SANDBOX_BY_PREFIX.clear()
        _SANDBOX_OWNER.clear()
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
        # Group kill: a timeout must not leave DOSBox's session (and any
        # helper it started) running after this call has returned.
        r = run_process_group(
            ["dosbox", "-conf", str(conf), "-noconsole"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
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


#: Directories of a vendored 16-bit compiler tree linked into its sandbox.
TREE_SUBDIRS = ("BIN", "INCLUDE", "LIB")

#: Fixed 8.3-safe name the staged source is compiled under: DOSBox truncates
#: long names and the 16-bit compilers reject the truncated stem (C1083).
STAGED_SOURCE_NAME = "SRC.C"


def stage_tree_source(
    sandbox: Path, tree: Path, c_source: str | Path, staged_name: str = STAGED_SOURCE_NAME
) -> str:
    """Stage *c_source* into *sandbox* beside a symlinked *tree*, for DOSBox.

    Links the vendored compiler tree's :data:`TREE_SUBDIRS` into the sandbox
    (DOSBox follows host symlinks), writes *c_source* there as *staged_name*,
    and drops any ``.OBJ`` that stem already produced, so a reused
    caller-supplied *sandbox* cannot report the previous run's object as this
    one's.  Returns the source's own name, for the error message when the
    compiler produces no object.

    The write is by raw bytes: a UTF-8 ``errors="replace"`` round-trip
    permanently turns legacy bytes (Shift-JIS / CP1252 string literals in
    Japanese-era TUs) into U+FFFD, so the DOS compiler never sees the
    original encoding.  A path source is copied byte-for-byte; in-memory text
    is written as UTF-8 + surrogateescape.
    """
    src_path = Path(c_source) if Path(c_source).exists() else None
    if src_path is not None:
        src_name = src_path.name
        staged_bytes = src_path.read_bytes()
    else:
        src_name = "probe.c"
        staged_bytes = str(c_source).encode("utf-8", errors="surrogateescape")

    sandbox.mkdir(parents=True, exist_ok=True)
    for sub in TREE_SUBDIRS:
        link = sandbox / sub
        target = tree / sub
        # Replace a stale symlink when the sandbox is reused with a different
        # compiler version (a workdir staged for one version must not silently
        # keep compiling with it when another is requested).
        if link.is_symlink() and link.resolve() != target.resolve():
            link.unlink()
        if not link.exists():
            link.symlink_to(target, target_is_directory=True)
    (sandbox / staged_name).write_bytes(staged_bytes)
    _drop_stale_object(sandbox, Path(staged_name).stem)
    return src_name


def find_staged_object(sandbox: Path, staged_name: str = STAGED_SOURCE_NAME) -> Path | None:
    """The ``.OBJ`` the staged *staged_name* produced, or ``None``."""
    stem = Path(staged_name).stem.upper()
    return next(
        (p for p in sandbox.iterdir() if p.suffix.upper() == ".OBJ" and p.stem.upper() == stem),
        None,
    )


def _drop_stale_object(sandbox: Path, stem: str) -> None:
    upper = stem.upper()
    for stale in sandbox.iterdir():
        if stale.suffix.upper() == ".OBJ" and stale.stem.upper() == upper:
            stale.unlink()


__all__ = [
    "STAGED_SOURCE_NAME",
    "TREE_SUBDIRS",
    "DosboxError",
    "find_staged_object",
    "make_sandbox_dir",
    "read_uppercase",
    "release_sandbox",
    "run_dosbox",
    "stage_tree_source",
]
