"""Headless X server management for Wine compiler invocations.

Wine prefixes configured with "Emulate a virtual desktop" (winecfg) pop a
window on every compiler invocation, and bare ``wine`` fails outright under
CI with no ``DISPLAY``.  The robust fix is to point ``wine`` at a virtual
display owned by an ``Xvfb`` server.  ``xvfb-run`` does this per invocation
but its wrapper script costs ~3 s of overhead each time — worse than the
compiles it wraps.  Instead we keep **one persistent Xvfb per process**
(reusing any live Xvfb left by an earlier rebrew run), so the startup cost
is paid once and amortized across every compile in a verify/GA batch.

Process lifecycle: the first ``ensure_xvfb_session()`` call spawns ``Xvfb`` on a
free display (or reuses an existing one), registers an atexit handler to
shut it down, and remembers the display in ``REBREW_XVFB_DISPLAY`` so
child processes and later calls agree on the same server.  A SIGKILLed
rebrew leaves an orphan Xvfb behind; the next run finds it via the
``/proc`` scan and reuses it instead of spawning another.

Authentication: the server rebrew starts is handed an ``-auth`` file (mode
0600) exported as ``XAUTHORITY`` for the wine children, and an existing Xvfb
is adopted only when this process can read the server's recorded ``-auth``
file or its own ``XAUTHORITY``.  The started file holds a real xauth record
(``MIT-MAGIC-COOKIE-1`` for the display's hostname and number), so the server
refuses clients without the cookie.  Adoption of a server rebrew did not
start still depends on a readable cookie file, which does not prove the
server enforces it.
"""

from __future__ import annotations

import logging
import re
import threading
from pathlib import Path
lazy import atexit
lazy import contextlib
lazy import os
lazy import secrets
lazy import shutil
lazy import socket
lazy import struct
lazy import subprocess
lazy import tempfile
lazy import time
lazy from collections.abc import Callable

from rebrew.config import XVFB_DISPLAY_ENV as _XVFB_DISPLAY_ENV
lazy from rebrew.config import check_env_display

log = logging.getLogger(__name__)

#: Screen geometry for the virtual display.  24-bit depth is required for
#: some Wine versions (the xvfb-run 8-bit default breaks them).  Kept as
#: separate argv tokens — Xvfb does NOT shell-split its args, so a single
#: "-screen 0 1280x1024x24" string makes it fail to start (the geometry
#: becomes an unexpected positional).  Join with spaces for ``xvfb-run -s``.
_XVFB_SCREEN = ("-screen", "0", "1280x1024x24")
XVFB_RUN_SERVER_ARGS = " ".join(_XVFB_SCREEN)

#: Env var recording the display our Xvfb (or a reused one) lives on.
#: Named in :mod:`rebrew.config` so ``rebrew cfg effective`` validates an
#: operator-pinned value against the same string this module writes.
XVFB_DISPLAY_ENV = _XVFB_DISPLAY_ENV

#: Env var the spawned Xvfb carries, naming the ``-auth`` file it was started
#: with, so a later rebrew process can find the same file for an orphan server
#: instead of trusting whatever Xvfb it discovers.
_XVFB_AUTH_ENV = "REBREW_XVFB_AUTH"

#: Bytes of random token written to the Xvfb ``-auth`` file (the xvfb-run
#: default).
_XVFB_COOKIE_BYTES = 16

#: X authorization protocol the cookie record names.
_XVFB_AUTH_PROTOCOL = b"MIT-MAGIC-COOKIE-1"

#: Xauth address family for a local hostname entry.
_XAUTH_FAMILY_LOCAL = 256

#: Display range rebrew is allowed to use.  Real desktops live on :0/:1, so
#: scanning this range only ever collides with other virtual servers.
_XVFB_DISPLAY_RANGE = range(90, 200)

#: Serializes :func:`ensure_xvfb`.  Compile worker threads all call it on the
#: first compile of a batch; without the lock, two threads can pass the
#: "no display yet" checks simultaneously, pick the same free display, and
#: both spawn an Xvfb (the loser dies with "server already active", leaking
#: a zombie child and racing the winner's socket probe).
_XVFB_INIT_LOCK = threading.Lock()

#: Socket dir X servers bind (patchable in tests).  Xvfb binds under
#: ``TMPDIR`` (falling back to ``/tmp``), so :func:`_xvfb_socket_dir` reads
#: it at call time rather than freezing ``/tmp`` at import: a sandboxed/CI
#: run with ``TMPDIR`` on another filesystem would otherwise probe a dir
#: Xvfb never writes to.  Tests monkeypatch ``_XVFB_SOCKET_DIR``; when that
#: value still equals the import-time default, the live ``TMPDIR`` dir wins.
_XVFB_SOCKET_DIR = Path("/tmp/.X11-unix")


def _xvfb_socket_dir() -> Path:
    if Path("/tmp/.X11-unix") != _XVFB_SOCKET_DIR:
        return _XVFB_SOCKET_DIR
    return Path(tempfile.gettempdir()) / ".X11-unix"


#: The display is Xvfb's first argv token, so match it on the token boundary.
#: A greedy ``[^\n]*:(\d+)`` would key the map on the LAST ``:N`` in the
#: cmdline, and any later argument carrying one mis-keys the display.
_XVFB_PROC_RE = re.compile(r"Xvfb\s+(:\d+)(?:\s|$)")

#: Every Xvfb this process spawned, as ``(process, cookie file)``, oldest
#: first.  A server that died under us (OOM kill, host reboot) is reaped and
#: its cookie unlinked on the next :func:`_ensure_xvfb_locked`, so a respawn
#: loop over a flapping display does not grow this list, and one atexit hook
#: drains whatever is still live instead of one callback pair per generation.
#: Guarded by ``_XVFB_INIT_LOCK``, which every writer and reader holds.
_owned_xvfb: list[tuple[subprocess.Popen[bytes], Path]] = []
_xvfb_atexit_registered = False


def _proc_environ(pid: int) -> dict[str, str]:
    """Environment of process *pid* (``/proc`` walk, no external tool)."""
    try:
        raw = (Path("/proc") / str(pid) / "environ").read_bytes()
    except OSError:
        return {}
    env: dict[str, str] = {}
    for item in raw.split(b"\0"):
        key, sep, value = item.partition(b"=")
        if sep:
            env[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
    return env


def _readable_cookie(path: Path) -> Path | None:
    """*path* when it is a cookie file this user can actually open."""
    try:
        if path.is_file() and os.access(path, os.R_OK):
            return path
    except OSError:
        return None
    return None


def _server_cookie(pid: int) -> Path | None:
    """Cookie file the Xvfb *pid* was started with, when we can read it.

    An X server started without ``-auth`` accepts every client that can reach
    its socket, and that socket lives in the world-writable ``/tmp/.X11-unix``:
    another local user could read every window wine draws (compiler output,
    the source under test) and inject events into it.  This probe returns only
    a readable cookie file recorded for the server; :func:`_adopt` falls back
    to the process's own ``XAUTHORITY`` when it returns ``None``.
    """
    raw = _proc_environ(pid).get(_XVFB_AUTH_ENV, "")
    return _readable_cookie(Path(raw)) if raw else None


def _local_cookie() -> Path | None:
    """``XAUTHORITY`` from our own environment.

    ``xvfb-run`` and a prior rebrew run both set it, so an operator-supplied
    ``XAUTHORITY`` stays reusable.

    ``~`` is expanded: a quoted ``XAUTHORITY='~/.Xauthority'`` reaches the
    process as a literal, and without expansion the cookie is unreadable, so
    rebrew starts a second Xvfb instead of adopting the operator's.
    """
    raw = os.environ.get("XAUTHORITY", "").strip()
    return _readable_cookie(Path(raw).expanduser()) if raw else None


def _xauth_record(hostname: bytes, display_number: bytes, cookie: bytes) -> bytes:
    """One binary Xauthority entry, as ``xauth add`` writes it.

    Each field is a big-endian u16 length followed by its bytes, in the
    order family, address, display number, protocol name, cookie.
    """
    parts = (
        struct.pack(">H", _XAUTH_FAMILY_LOCAL),
        hostname,
        display_number,
        _XVFB_AUTH_PROTOCOL,
        cookie,
    )
    return b"".join(
        struct.pack(">H", len(part)) + part if i else part for i, part in enumerate(parts)
    )


def _new_cookie(display: str) -> Path | None:
    """Owner-only file holding a fresh MIT-MAGIC-COOKIE-1 record for ``-auth``.

    The record names this host and *display*'s number, the two fields the
    server and the client match on, so a client without the cookie is
    refused.  The display number is derived from *display* (``:99`` or
    ``:99.0``); a spelling without one falls back to the text after ``:``.
    """
    number = _server_display(display).removeprefix(":") or "0"
    hostname = socket.gethostname().encode("utf-8", "replace")
    record = _xauth_record(
        hostname,
        number.encode("ascii"),
        secrets.token_bytes(_XVFB_COOKIE_BYTES),
    )
    try:
        fd, name = tempfile.mkstemp(prefix="rebrew-xvfb-", suffix=".cookie")
    except OSError:
        return None
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(record)
    except BaseException:
        # A short write leaves a cookie file that no display will ever read and
        # that no caller holds a path to, so the unlink below never runs.
        _drop_cookie(Path(name))
        raise
    return Path(name)


def _drop_cookie(cookie: Path) -> None:
    with contextlib.suppress(OSError):
        cookie.unlink()


def _adopt(display: str, pid: int) -> bool:
    """Take over live Xvfb *display* when this process can read a cookie for it.

    Records the display and the cookie in the environment so the wine children
    :func:`rebrew.compiler.compile.maybe_headless_wine` builds inherit ``XAUTHORITY``.
    Caller must hold ``_XVFB_INIT_LOCK``; the two environment writes and the
    cookie they belong to have to become visible together (see
    :func:`xvfb_cookie_for`).
    """
    cookie = _server_cookie(pid) or _local_cookie()
    if cookie is None:
        return False
    os.environ["XAUTHORITY"] = str(cookie)
    os.environ[XVFB_DISPLAY_ENV] = display
    return True


def xvfb_cookie_for(display: str) -> str:
    """``XAUTHORITY`` recorded for *display*, or ``""`` when the pair disagrees.

    The cookie and the display are two separate ``os.environ`` writes, and a
    compile worker reads them from :func:`rebrew.compiler.compile.maybe_headless_wine`
    with no init lock held.  Reading the pair under ``_XVFB_INIT_LOCK`` is what
    keeps a worker from picking up the new display alongside the previous
    server's cookie, which would hand wine a cookie recorded for another
    display.
    """
    with _XVFB_INIT_LOCK:
        if os.environ.get(XVFB_DISPLAY_ENV) != display:
            return ""
        return os.environ.get("XAUTHORITY", "")


def _server_display(display: str) -> str:
    """The ``:N`` server part of *display*, dropping any ``.S`` screen suffix.

    ``:99.0`` and ``:99`` name one X server, but only ``:N`` is a key the
    ``/proc`` scan produces and only ``:N`` has a socket under
    :data:`_XVFB_SOCKET_DIR`.  The suffix is the client's screen selection,
    so it stays in the value handed back to the caller.
    """
    return display.partition(".")[0]


def _display_alive(display: str) -> bool:
    """True when the X server for *display* (e.g. ``:99``, ``:99.0``) has a socket."""
    return (_xvfb_socket_dir() / f"X{_server_display(display).removeprefix(':')}").exists()


def _running_xvfb_displays() -> dict[str, int]:
    """Map ``:N`` -> pid for every live Xvfb process (``/proc`` scan, empty off Linux).

    The scan is a Linux-only probe: on macOS/BSD/Windows ``/proc`` does not
    exist, so this returns ``{}`` and callers fall back to the socket check
    without assuming a process list.  The claim is qualified Linux glibc /
    macOS ARM64 / Windows AMD64 hosts, but only Linux has ``/proc``; the
    socket probe is the portable path and the scan is an optimisation.
    """
    out: dict[str, int] = {}
    try:
        proc_dir = Path("/proc")
        if not proc_dir.is_dir():
            return out
        for entry in proc_dir.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cmdline = (
                    (entry / "cmdline")
                    .read_bytes()
                    .replace(b"\0", b" ")
                    .decode("utf-8", errors="replace")
                )
            except OSError:
                continue
            m = _XVFB_PROC_RE.search(cmdline)
            if m is not None:
                out[m.group(1)] = int(entry.name)
    except OSError:
        pass
    return out


def _pick_free_display() -> str | None:
    """Lowest display in the allowed range without a live X socket.

    ``None`` when every display in the range is taken.  Returning a
    ``pid % range`` guess instead put two servers on one display under load:
    the loser exits "Server is already active", and the socket probe could
    then accept the winner's socket as its own.  The caller falls back to
    ``xvfb-run``, which owns its display reservation.
    """
    for n in _XVFB_DISPLAY_RANGE:
        if not (_xvfb_socket_dir() / f"X{n}").exists():
            return f":{n}"
    return None


#: Poll interval of :func:`_wait_for_socket` against a real clock.
_SOCKET_POLL_INTERVAL_S = 0.05


def _wait_for_socket(
    display: str,
    timeout: float = 3.0,
    proc: subprocess.Popen[bytes] | None = None,
    *,
    clock: Callable[[], float] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> bool:
    """Poll until the X server's socket appears (it may take ~200-400 ms).

    When *proc* is given, bail early if the process exits — a server that
    dies during startup (bad args, missing deps) would otherwise burn the
    whole timeout on every call.

    *clock* and *sleep* are the loop's only time sources, the same seam
    :func:`rebrew.match_ga.BinaryMatchingGA.run` and
    :func:`rebrew.matcher.compiler.flag_sweep` take: inject both to replay a
    startup sequence from virtual time, with no real waiting and no
    dependence on how fast this machine spawns Xvfb.
    """
    now = clock if clock is not None else time.monotonic
    nap = sleep if sleep is not None else time.sleep
    sock = _xvfb_socket_dir() / f"X{display.removeprefix(':')}"
    deadline = now() + timeout
    proc_pid = getattr(proc, "pid", None)
    while now() < deadline:
        # A child that exited did not publish a server, even if another
        # process's socket is already at this display.
        if proc is not None and proc.poll() is not None:
            return False
        if sock.exists():
            if not isinstance(proc_pid, int) or proc_pid <= 0:
                return True
            if Path("/proc").is_dir():
                # The socket path alone cannot say which server bound it.
                # A lost display race leaves a peer's Xvfb owning it while
                # our child is still exiting; accepting that socket pairs
                # our cookie with a server that will refuse it.
                if _running_xvfb_displays().get(_server_display(display)) == proc_pid:
                    return True
            else:
                return True
        nap(_SOCKET_POLL_INTERVAL_S)
    return False


def _shutdown_xvfb(proc: subprocess.Popen[bytes]) -> None:
    """atexit hook — terminate the Xvfb this process spawned.

    A server that ignores SIGTERM must not survive this process holding
    its display socket, nor linger as an unreaped child for the rest of
    the batch — escalate to SIGKILL when the graceful wait times out.
    The child leads its own session (``start_new_session=True``), so the
    whole group is signalled rather than only the direct child.
    """
    # Build the group kill lazily so the test stub (no pid) still exercises
    # the terminate->kill escalation path; stop_process_tree needs a real
    # pid to snapshot descendants.
    pid = getattr(proc, "pid", None)
    if isinstance(pid, int) and pid > 1:
        try:
            from rebrew.utils import stop_process_tree

            stop_process_tree(proc)
            return
        except Exception as exc:
            log.debug("stop_process_tree failed for Xvfb pid %r: %s", pid, exc)
    with contextlib.suppress(Exception):
        proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(Exception):
            proc.kill()
        with contextlib.suppress(Exception):
            proc.wait(timeout=2)


def _reap_dead_xvfb() -> None:
    """Retire the generations of Xvfb that have already exited.

    ``poll`` is the reap: a server whose process is gone is collected here
    instead of lingering as a zombie, and its cookie file goes with it.  The
    file is a per-run temp artefact, not an access-control credential (see the
    module docstring), so it should not outlive the server it belongs to.
    """
    dead = [entry for entry in _owned_xvfb if entry[0].poll() is not None]
    if dead:
        retiring = set(dead)
        _owned_xvfb[:] = [entry for entry in _owned_xvfb if entry not in retiring]
    for entry in dead:
        _drop_cookie(entry[1])


def _release_owned_xvfb() -> None:
    """atexit hook: shut down every Xvfb this process still owns."""
    with _XVFB_INIT_LOCK:
        pending = list(_owned_xvfb)
        _owned_xvfb.clear()
    for proc, cookie in reversed(pending):
        _shutdown_xvfb(proc)
        _drop_cookie(cookie)


def ensure_xvfb_session() -> tuple[str, str] | None:
    """Return ``(display, XAUTHORITY)`` for a live Xvfb as one locked read.

    :func:`ensure_xvfb` and :func:`xvfb_cookie_for` are two separate
    acquisitions, so a peer can republish a different display between them
    (or between the selection and a copy of ``os.environ``).  A caller that
    hands both values to a child needs the pair from the same generation:
    selecting the cookie after the fact can return "" for the display it was
    given and leave the child with a peer's cookie for another server.  The
    cookie is "" when the selected display has none recorded.
    """
    with _XVFB_INIT_LOCK:
        display = _ensure_xvfb_locked()
        if display is None:
            return None
        if os.environ.get(XVFB_DISPLAY_ENV) != display:
            return display, ""
        return display, os.environ.get("XAUTHORITY", "")


def ensure_xvfb() -> str | None:
    """Return a display string for a live Xvfb, starting one if necessary.

    Resolution order (a live server is adopted only when a readable cookie
    file is available for it; a server with none is left alone and a private
    one is started instead):
    1. ``REBREW_XVFB_DISPLAY`` — set by a previous call in this process (or
       inherited from a parent), if its server is still alive.
    2. The current ``DISPLAY``, when it is owned by an Xvfb process (we are
       already running headless — no point spawning another server).
    3. Any other live Xvfb found via ``/proc`` (an orphan from a prior
       rebrew run), so separate processes share one server.
    4. Spawn our own ``Xvfb`` with an ``-auth`` file on a free display and
       register an atexit shutdown; remember it in ``REBREW_XVFB_DISPLAY``.

    Returns None when no Xvfb binary is available, or when starting one
    fails (caller falls back to the ``xvfb-run`` wrapper or bare wine).  A
    start failure is logged: the fallback itself is silent, so without the
    line a run whose headless setup never worked has no trace of it.

    Thread-safe: the whole resolution runs under one process-wide lock so
    concurrent compile workers cannot double-spawn a server on the same
    display (check-then-act on the socket, ``/proc`` scan, and env var).
    A caller that also needs the cookie must use
    :func:`ensure_xvfb_session`, not a second call to
    :func:`xvfb_cookie_for`.
    """
    session = ensure_xvfb_session()
    return None if session is None else session[0]


def _ensure_xvfb_locked() -> str | None:
    """Body of :func:`ensure_xvfb`; caller must hold ``_XVFB_INIT_LOCK``."""
    global _xvfb_atexit_registered
    _reap_dead_xvfb()
    displays = _running_xvfb_displays()
    env_display = os.environ.get(XVFB_DISPLAY_ENV, "")
    # An unusable spelling is refused here rather than skipped below: a
    # hostname display or a missing colon can never be adopted, so the run
    # would silently compile on some other display than the one the operator
    # pinned.  Same parser ``rebrew cfg effective`` reports, so the two agree.
    check_env_display(env_display)
    # The env display is trusted only when a LIVE Xvfb process owns it — a
    # socket check alone can resurrect a stale REBREW_XVFB_DISPLAY whose
    # server died (or whose socket was reused by a non-Xvfb X server),
    # sending every compile into a dead display.  Liveness is not enough to
    # adopt it: :func:`_adopt` also requires a readable cookie file for the
    # server, so a server with none is never reused.
    env_server = _server_display(env_display)
    if (
        env_server
        and env_server in displays
        and _display_alive(env_server)
        and _adopt(env_display, displays[env_server])
    ):
        return env_display

    current = os.environ.get("DISPLAY", "")
    current_server = _server_display(current)
    if current_server and current_server in displays and _adopt(current, displays[current_server]):
        return current
    for candidate in sorted(displays, key=lambda d: int(d[1:])):
        if _adopt(candidate, displays[candidate]):
            return candidate

    if shutil.which("Xvfb") is None:
        # Not a fault: a machine without Xvfb is configured to fall back, and
        # every compile asks again, so this stays off the warning stream.
        log.debug("no Xvfb binary on PATH; wine will run without a virtual display")
        return None

    # Display selection and binding are one cross-process critical section:
    # the process-local lock orders this process's workers, but two rebrew
    # processes can both see a display free and both spawn on it.  The
    # winner's socket then appears under the loser, whose ``proc`` may still
    # be alive long enough for the probe to accept it.  The lock is scoped to
    # the spawn path; adopting an existing server needs no reservation.
    from rebrew.utils import file_lock

    with file_lock(Path(tempfile.gettempdir()) / "rebrew-xvfb-start.lock"):
        display = _pick_free_display()
        if display is None:
            log.debug("every Xvfb display in the reserved range is in use")
            return None
        cookie = _new_cookie(display)
        if cookie is None:
            log.warning(
                "could not create an Xvfb cookie file; "
                "wine will run without a virtual display (temp dir unwritable?)"
            )
            return None
        child_env = {**os.environ, "XAUTHORITY": str(cookie), _XVFB_AUTH_ENV: str(cookie)}
        try:
            proc = subprocess.Popen(
                ["Xvfb", display, *_XVFB_SCREEN, "-nolisten", "tcp", "-auth", str(cookie)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=child_env,
                start_new_session=True,
            )
        except OSError as exc:
            _drop_cookie(cookie)
            log.warning(
                "could not start Xvfb on %s (%s); wine will run without a virtual display",
                display,
                exc.strerror or type(exc).__name__,
            )
            return None
        except BaseException:
            # A Ctrl+C landing in the spawn window would otherwise leave the
            # credential on disk and the child unreaped, since the atexit reaper
            # only learns about it below.
            _drop_cookie(cookie)
            raise
        # From here the pair is the reaper's responsibility: an interrupt before
        # the socket appears must not bypass cleanup either.
        _owned_xvfb.append((proc, cookie))
        if not _xvfb_atexit_registered:
            atexit.register(_release_owned_xvfb)
            _xvfb_atexit_registered = True
        if not _wait_for_socket(display, proc=proc):
            # Same release path as the atexit hook: terminate AND wait, so a
            # server that died during startup is reaped instead of lingering
            # as a zombie for the rest of this process's lifetime.
            exit_code = proc.poll()
            _shutdown_xvfb(proc)
            _drop_cookie(cookie)
            # The fallback is silent from here on, so without this the only trace
            # of a headless setup that never worked is a run whose wine compiles
            # behave differently from the ones the operator configured.
            log.warning(
                "Xvfb on %s never came up%s; wine will run without a virtual display",
                display,
                "" if exit_code is None else f" (exited {exit_code})",
            )
            return None
        os.environ["XAUTHORITY"] = str(cookie)
        os.environ[XVFB_DISPLAY_ENV] = display
        return display
