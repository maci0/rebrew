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
"""

from __future__ import annotations

import atexit
import contextlib
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

#: Screen geometry for the virtual display.  24-bit depth is required for
#: some Wine versions (the xvfb-run 8-bit default breaks them).  Kept as
#: separate argv tokens — Xvfb does NOT shell-split its args, so a single
#: "-screen 0 1280x1024x24" string makes it fail to start (the geometry
#: becomes an unexpected positional).
_XVFB_SCREEN = ("-screen", "0", "1280x1024x24")

#: Env var recording the display our Xvfb (or a reused one) lives on.
_XVFB_DISPLAY_ENV = "REBREW_XVFB_DISPLAY"

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
                    (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
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
    return f":{90 + os.getpid() % (_XVFB_DISPLAY_RANGE.stop - _XVFB_DISPLAY_RANGE.start)}"


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
    """atexit hook — terminate the Xvfb this process spawned."""
    with contextlib.suppress(Exception):
        proc.terminate()
    with contextlib.suppress(Exception):
        proc.wait(timeout=2)


def ensure_xvfb() -> str | None:
    """Return a display string for a live Xvfb, starting one if necessary.

    Resolution order:
    1. ``REBREW_XVFB_DISPLAY`` — set by a previous call in this process (or
       inherited from a parent), if its server is still alive.
    2. The current ``DISPLAY``, when it is owned by an Xvfb process (we are
       already running headless — no point spawning another server).
    3. Any other live Xvfb found via ``/proc`` (an orphan from a prior
       rebrew run), so separate processes share one server.
    4. Spawn our own ``Xvfb`` on a free display and register an atexit
       shutdown; remember it in ``REBREW_XVFB_DISPLAY``.

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
    env_display = os.environ.get(_XVFB_DISPLAY_ENV, "")
    if env_display and _display_alive(env_display):
        return env_display

    displays = _running_xvfb_displays()
    current = os.environ.get("DISPLAY", "")
    if current and current in displays:
        return current
    if displays:
        chosen = min(displays, key=lambda d: int(d[1:]))
        os.environ[_XVFB_DISPLAY_ENV] = chosen
        return chosen

    if shutil.which("Xvfb") is None:
        return None

    display = _pick_free_display()
    try:
        proc = subprocess.Popen(
            ["Xvfb", display, *_XVFB_SCREEN, "-nolisten", "tcp"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return None
    if not _wait_for_socket(display, proc=proc):
        # Same release path as the atexit hook: terminate AND wait, so a
        # server that died during startup is reaped instead of lingering
        # as a zombie for the rest of this process's lifetime.
        _shutdown_xvfb(proc)
        return None
    os.environ[_XVFB_DISPLAY_ENV] = display
    atexit.register(_shutdown_xvfb, proc)
    return display
