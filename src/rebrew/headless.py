"""Headless X server management for Wine compiler invocations.

Wine prefixes configured with "Emulate a virtual desktop" (winecfg) pop a
window on every compiler invocation, and bare ``wine`` fails outright under
CI with no ``DISPLAY``.  The robust fix is to point ``wine`` at a virtual
display owned by an ``Xvfb`` server.  ``xvfb-run`` does this per invocation
but its wrapper script costs ~3 s of overhead each time — worse than the
compiles it wraps.  Instead we keep **one persistent Xvfb per process**
(reusing any live Xvfb left by an earlier rebrew run), so the startup cost
is paid once and amortized across every compile in a verify/GA batch.

Process lifecycle: the first ``ensure_xvfb()`` call spawns ``Xvfb`` on a
free display (or reuses an existing one), registers an atexit handler to
shut it down, and remembers the display in ``REBREW_XVFB_DISPLAY`` so
child processes and later calls agree on the same server.  A SIGKILLed
rebrew leaves an orphan Xvfb behind; the next run finds it via the
``/proc`` scan and reuses it instead of spawning another.

Authentication: the server rebrew starts carries a fresh MIT-MAGICK cookie
(``-auth``, cookie file mode 0600) exported as ``XAUTHORITY`` for the wine
children, and an existing Xvfb is adopted only when this process holds a
cookie that authenticates to it.  An X server without access control accepts
any local client that can reach its world-writable ``/tmp/.X11-unix``
socket, which would let another user on the box read the windows wine draws
and inject events into them.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from rebrew.config import XVFB_DISPLAY_ENV as _XVFB_DISPLAY_ENV

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

#: Env var the spawned Xvfb carries, naming the MIT-MAGICK cookie file it was
#: started with, so a later rebrew process can authenticate to an orphan
#: server instead of trusting whatever Xvfb it finds.
_XVFB_AUTH_ENV = "REBREW_XVFB_AUTH"

#: Bytes of MIT-MAGICK cookie per server (the xvfb-run default).
_XVFB_COOKIE_BYTES = 16

#: Display range rebrew is allowed to use.  Real desktops live on :0/:1, so
#: scanning this range only ever collides with other virtual servers.
_XVFB_DISPLAY_RANGE = range(90, 200)

#: Serializes :func:`ensure_xvfb`.  Compile worker threads all call it on the
#: first compile of a batch; without the lock, two threads can pass the
#: "no display yet" checks simultaneously, pick the same free display, and
#: both spawn an Xvfb (the loser dies with "server already active", leaking
#: a zombie child and racing the winner's socket probe).
_XVFB_INIT_LOCK = threading.Lock()

#: Socket dir X servers bind (patchable in tests).
_XVFB_SOCKET_DIR = Path("/tmp/.X11-unix")

_XVFB_PROC_RE = re.compile(r"Xvfb[^\n]*:(\d+)")


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
    the source under test) and inject events into it.  A server is only
    adoptable when this process holds the cookie that authenticates to it.
    """
    raw = _proc_environ(pid).get(_XVFB_AUTH_ENV, "")
    return _readable_cookie(Path(raw)) if raw else None


def _local_cookie() -> Path | None:
    """``XAUTHORITY`` from our own environment.

    ``xvfb-run`` and a prior rebrew run both set it, so an operator-supplied
    authenticated server stays reusable.
    """
    raw = os.environ.get("XAUTHORITY", "").strip()
    return _readable_cookie(Path(raw)) if raw else None


def _new_cookie() -> Path | None:
    """Owner-only cookie file holding a fresh MIT-MAGICK cookie."""
    try:
        fd, name = tempfile.mkstemp(prefix="rebrew-xvfb-", suffix=".cookie")
    except OSError:
        return None
    with os.fdopen(fd, "w") as fh:
        fh.write(secrets.token_hex(_XVFB_COOKIE_BYTES) + "\n")
    return Path(name)


def _drop_cookie(cookie: Path) -> None:
    with contextlib.suppress(OSError):
        cookie.unlink()


def _adopt(display: str, pid: int) -> bool:
    """Take over live Xvfb *display* when this process can authenticate to it.

    Records the display and the cookie in the environment so the wine children
    :func:`rebrew.compile.maybe_headless_wine` builds inherit ``XAUTHORITY``.
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
    compile worker reads them from :func:`rebrew.compile.maybe_headless_wine`
    with no init lock held.  Reading the pair under ``_XVFB_INIT_LOCK`` is what
    keeps a worker from picking up the new display alongside the previous
    server's cookie, which would hand wine a cookie it cannot authenticate with
    against the display it was told to draw into.
    """
    with _XVFB_INIT_LOCK:
        if os.environ.get(XVFB_DISPLAY_ENV) != display:
            return ""
        return os.environ.get("XAUTHORITY", "")


def _display_alive(display: str) -> bool:
    """True when the X server for *display* (e.g. ``:99``) has a socket."""
    return (_XVFB_SOCKET_DIR / f"X{display.removeprefix(':')}").exists()


def _running_xvfb_displays() -> dict[str, int]:
    """Map ``:N`` -> pid for every live Xvfb process (cheap /proc scan)."""
    out: dict[str, int] = {}
    try:
        proc_dir = Path("/proc")
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
                out[f":{m.group(1)}"] = int(entry.name)
    except OSError:
        pass
    return out


def _pick_free_display() -> str:
    """Lowest display in the allowed range without a live X socket."""
    for n in _XVFB_DISPLAY_RANGE:
        if not (_XVFB_SOCKET_DIR / f"X{n}").exists():
            return f":{n}"
    return f":{_XVFB_DISPLAY_RANGE.start + os.getpid() % (_XVFB_DISPLAY_RANGE.stop - _XVFB_DISPLAY_RANGE.start)}"


def _wait_for_socket(
    display: str, timeout: float = 3.0, proc: subprocess.Popen[bytes] | None = None
) -> bool:
    """Poll until the X server's socket appears (it may take ~200-400 ms).

    When *proc* is given, bail early if the process exits — a server that
    dies during startup (bad args, missing deps) would otherwise burn the
    whole timeout on every call.
    """
    sock = _XVFB_SOCKET_DIR / f"X{display.removeprefix(':')}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if sock.exists():
            return True
        if proc is not None and proc.poll() is not None:
            return False
        time.sleep(0.05)
    return False


def _shutdown_xvfb(proc: subprocess.Popen[bytes]) -> None:
    """atexit hook — terminate the Xvfb this process spawned.

    A server that ignores SIGTERM must not survive this process holding
    its display socket, nor linger as an unreaped child for the rest of
    the batch — escalate to SIGKILL when the graceful wait times out.
    """
    with contextlib.suppress(Exception):
        proc.terminate()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(Exception):
            proc.kill()
        with contextlib.suppress(Exception):
            proc.wait(timeout=2)


def ensure_xvfb() -> str | None:
    """Return a display string for a live Xvfb, starting one if necessary.

    Resolution order (a live server is adopted only when this process holds
    the cookie that authenticates to it; an unauthenticated Xvfb found on the
    machine is left alone and a private one is started instead):
    1. ``REBREW_XVFB_DISPLAY`` — set by a previous call in this process (or
       inherited from a parent), if its server is still alive.
    2. The current ``DISPLAY``, when it is owned by an Xvfb process (we are
       already running headless — no point spawning another server).
    3. Any other live Xvfb found via ``/proc`` (an orphan from a prior
       rebrew run), so separate processes share one server.
    4. Spawn our own cookie-authenticated ``Xvfb`` on a free display and
       register an atexit shutdown; remember it in ``REBREW_XVFB_DISPLAY``.

    Returns None when no Xvfb binary is available (caller falls back to
    the ``xvfb-run`` wrapper or bare wine).

    Thread-safe: the whole resolution runs under one process-wide lock so
    concurrent compile workers cannot double-spawn a server on the same
    display (check-then-act on the socket, ``/proc`` scan, and env var).
    """
    with _XVFB_INIT_LOCK:
        return _ensure_xvfb_locked()


def _ensure_xvfb_locked() -> str | None:
    """Body of :func:`ensure_xvfb`; caller must hold ``_XVFB_INIT_LOCK``."""
    displays = _running_xvfb_displays()
    env_display = os.environ.get(XVFB_DISPLAY_ENV, "")
    # The env display is trusted only when a LIVE Xvfb process owns it — a
    # socket check alone can resurrect a stale REBREW_XVFB_DISPLAY whose
    # server died (or whose socket was reused by a non-Xvfb X server),
    # sending every compile into a dead display.  Liveness is not enough to
    # adopt it: :func:`_adopt` also requires the cookie that authenticates to
    # the server, so an unauthenticated Xvfb is never reused.
    if (
        env_display
        and env_display in displays
        and _display_alive(env_display)
        and _adopt(env_display, displays[env_display])
    ):
        return env_display

    current = os.environ.get("DISPLAY", "")
    if current and current in displays and _adopt(current, displays[current]):
        return current
    for candidate in sorted(displays, key=lambda d: int(d[1:])):
        if _adopt(candidate, displays[candidate]):
            return candidate

    if shutil.which("Xvfb") is None:
        return None

    display = _pick_free_display()
    cookie = _new_cookie()
    if cookie is None:
        return None
    child_env = {**os.environ, "XAUTHORITY": str(cookie), _XVFB_AUTH_ENV: str(cookie)}
    try:
        proc = subprocess.Popen(
            ["Xvfb", display, *_XVFB_SCREEN, "-nolisten", "tcp", "-auth", str(cookie)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=child_env,
        )
    except OSError:
        _drop_cookie(cookie)
        return None
    if not _wait_for_socket(display, proc=proc):
        # Same release path as the atexit hook: terminate AND wait, so a
        # server that died during startup is reaped instead of lingering
        # as a zombie for the rest of this process's lifetime.
        _shutdown_xvfb(proc)
        _drop_cookie(cookie)
        return None
    os.environ["XAUTHORITY"] = str(cookie)
    os.environ[XVFB_DISPLAY_ENV] = display
    atexit.register(_shutdown_xvfb, proc)
    atexit.register(_drop_cookie, cookie)
    return display
