"""temp_dirs.py — scratch directories that survive a hard-killed run.

Compile sandboxes cannot live in the system temp dir (often tmpfs, and
invisible to docker in a sandboxed environment), so :func:`writable_temp_dir`
prefers a real-disk, container-visible base and says so when none exists.
That placement is the whole reason this concern is separate from
:mod:`rebrew.utils`: the candidate order, the sweep of abandoned sandboxes,
and the DOSBox tmpfs rejection are one policy, and the rest of ``utils`` is
identifier text, source reading, and atomic writes.
"""

import contextlib
import logging
import os
import re
import threading
import time
from pathlib import Path

from rebrew.utils import SOURCE_CHECKOUT

__all__ = [
    "STALE_TEMP_DIR_AGE_S",
    "on_ram_filesystem",
    "remove_temp_dir",
    "sweep_stale_temp_dirs",
    "writable_temp_dir",
    "xdg_cache_home",
]


def xdg_cache_home() -> Path:
    """Return ``$XDG_CACHE_HOME``, or ``~/.cache`` when unset, empty, or relative.

    The XDG Base Directory spec requires ignoring a relative value; honoring
    one would resolve against the cwd and hand docker a relative bind mount.
    """
    xdg = Path(os.environ.get("XDG_CACHE_HOME", "").strip())
    return xdg if xdg.is_absolute() else Path.home() / ".cache"


#: ``/proc/self/mountinfo`` (not ``/proc/mounts``): it lists every mount in
#: this process's mount namespace with its own mount point, so a bind-mounted
#: subdirectory is reported as such.  ``/proc/mounts`` collapses a bind mount
#: into the parent filesystem's entry and would answer "real disk" for a
#: tmpfs bind mount.
_MOUNTINFO = Path("/proc/self/mountinfo")

#: RAM-backed filesystems DOSBox 0.74-3 cannot drive (see :mod:`rebrew.dosbox`).
#: ``ramfs`` is tmpfs's non-size-limited twin and breaks it the same way.
_RAM_FS_TYPES = frozenset({"tmpfs", "ramfs"})


def on_ram_filesystem(path: Path) -> bool:
    """True when *path* resolves onto a RAM-backed filesystem.

    Answers "no" when ``/proc`` is unavailable (a namespace without it cannot
    be probed, and refusing every dir there would break the common case), and
    matches the *longest* mount point that prefixes *path* so a nested mount
    wins over its parent.
    """
    try:
        lines = _MOUNTINFO.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    try:
        target = path.resolve()
    except OSError:
        return False
    best: tuple[int, str] | None = None
    for line in lines:
        fields = line.split(" ")
        # "<id> <parent> <maj:min> <root> <mount point> ... - <fstype> ..."
        try:
            sep = fields.index("-")
            mount_point = fields[4]
            fstype = fields[sep + 1]
        except (IndexError, ValueError):
            continue
        # The kernel octal-escapes space, tab, newline and backslash.
        mount_point = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), mount_point)
        if target != Path(mount_point) and not target.is_relative_to(mount_point):
            continue
        if best is None or len(mount_point) > best[0]:
            best = (len(mount_point), fstype)
    return best is not None and best[1] in _RAM_FS_TYPES


#: A sandbox left in the shared base is presumed abandoned once nothing has
#: touched it for this long.  Long enough that a live rebrew process (whose
#: compiles are bounded by ``--timeout-min``) never has its own sandbox swept
#: from under it, short enough that a host that hard-kills runs does not fill
#: the cache dir with multi-GB stragglers.
STALE_TEMP_DIR_AGE_S = 24 * 60 * 60

#: Every :func:`writable_temp_dir` prefix starts with this, so a sweep of a
#: shared base (``SOURCE_CHECKOUT/.cache``) touches rebrew scratch and nothing
#: else that happens to live there.
_TEMP_DIR_PREFIX = "rebrew"

_TEMP_SWEEP_LOCK = threading.Lock()
_temp_swept_bases: set[Path] = set()


def sweep_stale_temp_dirs(
    base: Path, age_s: float = STALE_TEMP_DIR_AGE_S, *, now: float | None = None
) -> list[Path]:
    """Remove abandoned rebrew sandbox dirs from *base*; return what was removed.

    ``remove_temp_dir`` and the atexit hooks release a sandbox on every path a
    run can take, so what is left here is what a run that never got to clean up
    stranded: SIGKILL, an OOM kill, a host reboot, a container killed mid
    batch.  Each of those leaves a staged toolchain and a container workdir
    behind, and nothing in the codebase ever looks at the parent again, so the
    base grows by one full sandbox per lost run.

    A dir counts as abandoned when its mtime is older than *age_s*.  Writes into
    a live sandbox (staged headers, ``.obj`` output, the link log) move that
    mtime, and a sandbox whose writes have stopped for a whole day belongs to no
    run still doing work.

    *now* overrides the age reference, so a replay or a test decides the same
    sweep from a fixed instant instead of from when the process happened to run.
    """
    import shutil

    if now is None:
        now = time.time()
    removed: list[Path] = []
    try:
        # Sorted: iterdir yields readdir order, which the filesystem chooses,
        # so an unsorted walk makes the same tree sweep to a different list.
        entries = sorted(base.iterdir())
    except OSError:
        return removed
    for entry in entries:
        if not entry.name.startswith(_TEMP_DIR_PREFIX) or entry.is_symlink():
            continue
        try:
            if not entry.is_dir() or now - entry.stat().st_mtime < age_s:
                continue
        except OSError:
            continue
        try:
            shutil.rmtree(entry)
        except OSError as exc:
            # Busy mount, or a peer that recreated it: leave it for the next
            # run rather than failing the compile that asked for a temp dir.
            logging.getLogger(__name__).debug("could not sweep %s: %s", entry, exc)
            continue
        removed.append(entry)
    return removed


def _sweep_base_once(base: Path) -> None:
    """Sweep *base* of abandoned sandboxes, the first time this process uses it.

    Every compile asks for a workdir, so an unguarded sweep would re-walk the
    base (and re-``stat`` every leftover in it) once per compile.  The lock is
    held across the walk, not just the claim, so a second thread waits instead
    of creating its sandbox in a base this thread is still removing entries
    from.  Concurrent processes each sweep once, and the losers simply find the
    dir already gone.
    """
    with _TEMP_SWEEP_LOCK:
        if base in _temp_swept_bases:
            return
        try:
            sweep_stale_temp_dirs(base)
        except OSError:
            # A sweep failure must not fail the compile that triggered it, and
            # the base stays unclaimed so a later compile retries it.
            return
        # Claimed only after the walk, so a peer thread that arrives mid-sweep
        # still waits for this one instead of walking the base in parallel.
        _temp_swept_bases.add(base)


def writable_temp_dir(prefix: str, *, require_real_disk: bool = False) -> Path:
    """Create a writable temp dir on a real-disk, container-visible location.

    Compile sandboxes must live on a real disk: DOSBox breaks on tmpfs
    mounts, and the docker runner mounts the workdir at /work, so a
    sandbox under the system temp dir (often tmpfs, and invisible to
    docker in sandboxed environments) silently breaks the compile.  The
    user's cache dir is preferred when writable; when it is read-only
    (sandboxed homes / CI) fall back to the source checkout's ``.cache`` (editable installs only)
    (a real disk, visible to docker) and then the system temp dir.

    Cache sandboxes live under ``$XDG_CACHE_HOME/rebrew/tmp`` when that
    variable is set, otherwise ``~/.cache/rebrew/tmp``, so that a straggler
    left behind by a hard-killed run stays out of ``~`` and is trivially
    sweepable.  The first two candidates are swept of abandoned sandboxes
    once per process on the way in (see :func:`sweep_stale_temp_dirs`); the
    system temp dir is left alone, since it is shared with every other tool.

    *require_real_disk* additionally rejects a candidate sitting on tmpfs or
    ramfs, for the callers that mount the dir into DOSBox (see
    :mod:`rebrew.dosbox`) — preference order alone does not enforce it, since
    ``XDG_CACHE_HOME`` and the system temp dir are both commonly tmpfs.  The
    error names the constraint instead of handing back a dir DOSBox cannot
    drive, which fails much later and much less legibly.

    Raises :class:`OSError` when no candidate is writable."""
    import tempfile

    candidates = [(xdg_cache_home() / "rebrew" / "tmp", True)]
    if SOURCE_CHECKOUT is not None:
        candidates.append((SOURCE_CHECKOUT / ".cache", True))
    with contextlib.suppress(Exception):
        # Shared with every other tool on the box: never swept.
        candidates.append((Path(tempfile.gettempdir()), False))
    ram_only: list[Path] = []
    for base, sweepable in candidates:
        try:
            base.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        if require_real_disk and on_ram_filesystem(base):
            ram_only.append(base)
            continue
        if sweepable:
            _sweep_base_once(base)
        try:
            return Path(tempfile.mkdtemp(prefix=prefix, dir=base))
        except OSError:
            continue
    if ram_only:
        raise OSError(
            f"no candidate for temp dir {prefix!r} is on a real disk; "
            f"{', '.join(str(b) for b in ram_only)} "
            f"{'is' if len(ram_only) == 1 else 'are'} tmpfs or ramfs, which DOSBox cannot mount. "
            "Point XDG_CACHE_HOME at a real-disk directory."
        )
    raise OSError(f"no writable directory for temp dir {prefix!r}")


def remove_temp_dir(path: Path, retries: int = 5, delay: float = 0.2) -> None:
    """Remove a temp dir created by :func:`writable_temp_dir`.

    A container that has not released its mount yet makes the top-level
    dir non-removable ("Device or resource busy") even after its contents
    are gone; the short retry absorbs the unmount race so sandboxes do not
    accumulate empty shells in their parent.  Raises :class:`OSError` when
    the dir is still busy after *retries*.
    """
    import shutil

    # retries=0 would make the loop below vacuous: the dir would be neither
    # removed nor reported, silently stranding a temp dir.
    if retries < 1:
        raise ValueError(f"retries must be at least 1, got {retries}")
    for attempt in range(retries):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            if attempt == retries - 1:
                raise
            time.sleep(delay)
