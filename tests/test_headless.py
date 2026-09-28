"""Tests for rebrew.headless — persistent Xvfb management for headless wine."""

import os
import threading
from pathlib import Path
from typing import Any

import pytest

from rebrew.headless import (
    _display_alive,
    _pick_free_display,
    ensure_xvfb,
)


@pytest.fixture(autouse=True)
def _isolate_owned_xvfb() -> Any:
    """Give every test its own Xvfb ownership set.

    The module keeps the servers this process spawned so a dead one is
    reaped and a live one is shut down at exit; a test that spawns a fake
    must not leave it in that set for the next test to inherit.
    """
    from rebrew import headless

    saved = headless._owned_xvfb
    saved_flag = headless._xvfb_atexit_registered
    headless._owned_xvfb = []
    headless._xvfb_atexit_registered = False
    try:
        yield
    finally:
        headless._owned_xvfb = saved
        headless._xvfb_atexit_registered = saved_flag


class TestDisplayAlive:
    def test_socket_present(self, monkeypatch) -> None:
        from rebrew import headless

        monkeypatch.setattr(headless, "_XVFB_SOCKET_DIR", Path("/nonexistent"))
        assert not _display_alive(":99")
        assert not _display_alive("99")

    def test_display_without_colon(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew import headless

        (tmp_path / "X77").touch()
        monkeypatch.setattr(headless, "_XVFB_SOCKET_DIR", tmp_path)
        assert _display_alive(":77")
        assert _display_alive("77")


class TestPickFreeDisplay:
    def test_lowest_free(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew import headless

        (tmp_path / "X90").touch()
        (tmp_path / "X91").touch()
        monkeypatch.setattr(headless, "_XVFB_SOCKET_DIR", tmp_path)
        assert _pick_free_display() == ":92"

    def test_ignores_existing_x0(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew import headless

        monkeypatch.setattr(headless, "_XVFB_SOCKET_DIR", tmp_path)
        assert _pick_free_display() == ":90"


class TestEnsureXvfb:
    def test_reuses_env_display_when_alive(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew import headless

        # A stale REBREW_XVFB_DISPLAY (socket present, no live Xvfb process)
        # must NOT be reused — only a process-backed display qualifies.
        monkeypatch.setattr(headless, "_display_alive", lambda d: d == ":99")
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {":99": 1234})
        monkeypatch.setattr(headless, "_server_cookie", lambda pid: tmp_path / "cookie")
        monkeypatch.setenv("REBREW_XVFB_DISPLAY", ":99")
        assert ensure_xvfb() == ":99"
        assert os.environ["XAUTHORITY"] == str(tmp_path / "cookie")

    def test_ignores_unauthenticated_live_xvfb(self, tmp_path: Path, monkeypatch) -> None:
        """A live Xvfb nobody can authenticate to is never adopted.

        Its socket is world-reachable, so reusing it hands the compile to a
        server another local user can read and inject into; rebrew starts
        its own cookie-authenticated one instead.
        """
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.setenv("DISPLAY", "")
        monkeypatch.delenv("XAUTHORITY", raising=False)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {":99": 1})
        monkeypatch.setattr(headless, "_server_cookie", lambda pid: None)
        monkeypatch.setattr(
            headless.shutil, "which", lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None
        )
        monkeypatch.setattr(headless, "_wait_for_socket", lambda d, timeout=3.0, proc=None: True)

        class _FakeProc:
            def terminate(self) -> None:
                pass

            def poll(self) -> None:
                return None

            def wait(self, timeout: float | None = None) -> int:
                return 0

        monkeypatch.setattr(headless.subprocess, "Popen", lambda *a, **k: _FakeProc())
        result = ensure_xvfb()
        assert result is not None and result != ":99"
        assert Path(os.environ["XAUTHORITY"]).is_file()

    def test_env_display_stale_process_ignored(self, monkeypatch) -> None:
        """Socket exists but no Xvfb process owns it → not reused."""
        from rebrew import headless

        monkeypatch.setattr(headless, "_display_alive", lambda d: True)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {})
        monkeypatch.setenv("REBREW_XVFB_DISPLAY", ":99")
        monkeypatch.setenv("DISPLAY", "")
        # No live displays, so ensure_xvfb would spawn; with no Xvfb binary
        # available it must return None rather than the stale ":99".
        monkeypatch.setattr(headless.shutil, "which", lambda name: None)
        assert ensure_xvfb() is None

    def test_reuses_current_display_when_xvfb(self, tmp_path: Path, monkeypatch) -> None:
        """DISPLAY owned by an Xvfb (already headless) is reused as-is."""
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {":77": 1234})
        monkeypatch.setattr(headless, "_server_cookie", lambda pid: tmp_path / "cookie")
        monkeypatch.setenv("DISPLAY", ":77")
        assert ensure_xvfb() == ":77"

    def test_reuses_orphan_xvfb(self, tmp_path: Path, monkeypatch) -> None:
        """A live Xvfb left by a prior run is reused (lowest display)."""
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {":99": 1, ":77": 2})
        monkeypatch.setattr(headless, "_server_cookie", lambda pid: tmp_path / "cookie")
        monkeypatch.delenv("DISPLAY", raising=False)
        assert ensure_xvfb() == ":77"
        assert os.environ.get("REBREW_XVFB_DISPLAY") == ":77"

    def test_spawns_own_xvfb(self, monkeypatch) -> None:
        """No live Xvfb → spawn one on a free display and record it."""
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {})
        monkeypatch.setattr(
            headless.shutil, "which", lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None
        )
        monkeypatch.setattr(headless, "_wait_for_socket", lambda d, timeout=3.0, proc=None: True)
        spawned: list[list[str]] = []
        killed: list[int] = []

        class _FakeProc:
            def __init__(self, *a: Any, **k: Any) -> None:
                spawned.append(list(a[0]))

            def terminate(self) -> None:
                killed.append(1)

            def wait(self, timeout: float = 2) -> int:
                return 0

        monkeypatch.setattr(headless.subprocess, "Popen", _FakeProc)
        result = ensure_xvfb()
        assert result is not None and result.startswith(":")
        assert spawned and spawned[0][0] == "Xvfb"
        assert spawned[0][2:6] == [
            "-screen",
            "0",
            "1280x1024x24",
            "-nolisten",
        ]  # screen geometry as separate argv tokens — a single joined
        # "-screen 0 1280x1024x24" string makes Xvfb fail to start and
        # silently degrades every wine compile to the 3 s xvfb-run wrapper.
        # The display is not pinned: in the full suite the process may
        # already own a server on :90, so the spawn lands on the next free.
        assert spawned[0][1] == result
        assert spawned[0][6:] == ["tcp", "-auth", os.environ["XAUTHORITY"]]
        assert Path(os.environ["XAUTHORITY"]).is_file()
        assert os.environ.get("REBREW_XVFB_DISPLAY") == result

    def test_no_xvfb_binary_returns_none(self, monkeypatch) -> None:
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {})
        monkeypatch.setattr(headless.shutil, "which", lambda name: None)
        assert ensure_xvfb() is None

    def test_spawn_failure_returns_none(self, monkeypatch) -> None:
        """Xvfb binary present but Popen raises (e.g. EPERM) → None."""
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {})
        monkeypatch.setattr(
            headless.shutil, "which", lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None
        )

        def _boom(*a, **k):
            raise OSError("denied")

        monkeypatch.setattr(headless.subprocess, "Popen", _boom)
        assert ensure_xvfb() is None

    def test_socket_timeout_terminates_proc(self, monkeypatch) -> None:
        """Xvfb spawned but never comes up → terminated AND reaped (no
        zombie), returns None."""
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {})
        monkeypatch.setattr(
            headless.shutil, "which", lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None
        )
        monkeypatch.setattr(headless, "_wait_for_socket", lambda d, timeout=3.0, proc=None: False)
        terminated: list[bool] = []
        reaped: list[float | None] = []

        class _FakeProc:
            def terminate(self) -> None:
                terminated.append(True)

            def wait(self, timeout: float = 2) -> int:
                reaped.append(timeout)
                return 0

        monkeypatch.setattr(headless.subprocess, "Popen", lambda *a, **k: _FakeProc())
        assert ensure_xvfb() is None
        assert terminated
        assert reaped == [2]

    def test_shutdown_escalates_to_kill_on_terminate_timeout(self, tmp_path: Path) -> None:
        """An Xvfb that ignores SIGTERM is SIGKILLed and reaped instead of
        lingering (holding its display socket / unreaped zombie)."""
        import subprocess as sp

        from rebrew.headless import _shutdown_xvfb

        calls: list[str] = []

        class _StubbornProc:
            def terminate(self) -> None:
                calls.append("terminate")

            def kill(self) -> None:
                calls.append("kill")

            def wait(self, timeout: float | None = None) -> int:
                if calls[-1] == "terminate":
                    raise sp.TimeoutExpired("Xvfb", timeout or 2)
                calls.append(f"wait:{timeout}")
                return 0

        _shutdown_xvfb(_StubbornProc())  # must not raise
        assert calls == ["terminate", "kill", "wait:2"]

    def test_dead_generation_is_reaped_and_its_cookie_dropped(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A server that died under us is released at the next call.

        The display it held is respawned on, so a flapping Xvfb in a
        long-lived batch used to leave one unreaped child and one cookie
        file (the server's only credential) per death.
        """
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {})
        monkeypatch.setattr(
            headless.shutil, "which", lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None
        )
        monkeypatch.setattr(headless, "_wait_for_socket", lambda d, timeout=3.0, proc=None: True)
        monkeypatch.setattr(headless, "_new_cookie", lambda: tmp_path / "cookie-0")
        (tmp_path / "cookie-0").write_text("secret\n")

        class _DeadProc:
            def poll(self) -> int:
                return 1

            def terminate(self) -> None:
                raise AssertionError("a dead server must not be signalled")

        monkeypatch.setattr(headless.subprocess, "Popen", lambda *a, **k: _DeadProc())
        assert ensure_xvfb() is not None
        assert len(headless._owned_xvfb) == 1

        monkeypatch.setattr(headless, "_new_cookie", lambda: tmp_path / "cookie-1")
        (tmp_path / "cookie-1").write_text("secret\n")
        assert headless._ensure_xvfb_locked() is not None  # dead server swept on entry

        # Only the replacement is owned; the dead one was reaped and its
        # cookie, the server's only credential, went with it.
        assert [cookie for _, cookie in headless._owned_xvfb] == [tmp_path / "cookie-1"]
        assert not (tmp_path / "cookie-0").exists()

    def test_atexit_hook_is_registered_once_across_respawns(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """One exit hook drains every generation, not one per spawn.

        ``atexit`` has no bound, so a per-spawn registration grew the exit
        list for as long as the process lived.
        """
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.delenv("DISPLAY", raising=False)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {})
        monkeypatch.setattr(
            headless.shutil, "which", lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None
        )
        monkeypatch.setattr(headless, "_wait_for_socket", lambda d, timeout=3.0, proc=None: True)
        registered: list[Any] = []
        monkeypatch.setattr(headless.atexit, "register", lambda fn, *a: registered.append(fn))
        monkeypatch.setattr(headless, "_new_cookie", lambda: tmp_path / "cookie")

        class _LiveProc:
            def poll(self) -> None:
                return None

            def terminate(self) -> None:
                pass

            def wait(self, timeout: float = 2) -> int:
                return 0

        monkeypatch.setattr(headless.subprocess, "Popen", lambda *a, **k: _LiveProc())
        for generation in range(3):
            cookie = tmp_path / f"cookie{generation}"
            monkeypatch.setattr(headless, "_new_cookie", lambda cookie=cookie: cookie)
            assert ensure_xvfb() is not None
        assert registered == [headless._release_owned_xvfb]
        assert len(headless._owned_xvfb) == 3

        headless._release_owned_xvfb()
        assert headless._owned_xvfb == []

    def test_concurrent_callers_spawn_one_server(self, tmp_path: Path, monkeypatch) -> None:
        """Parallel compile workers calling ensure_xvfb must not double-spawn.

        Without the init lock, two threads can both pass the env/orphan
        checks before either records its display, pick the same free
        display, and spawn two Xvfb processes (one dies with "server
        already active").
        """
        from thread_util import join_all

        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.delenv("DISPLAY", raising=False)
        # Stateful /proc scan: once a worker spawns Xvfb, later workers must
        # see the live process (the env-display reuse now requires process
        # liveness, not just a socket).
        spawned_displays: list[str] = []

        def _fake_running() -> dict[str, int]:
            return dict.fromkeys(spawned_displays, 1)

        monkeypatch.setattr(headless, "_running_xvfb_displays", _fake_running)
        monkeypatch.setattr(headless, "_display_alive", lambda d: True)
        # The spawned server is adopted by the losing workers through the
        # cookie this process exported, exactly as a real orphan would be.
        monkeypatch.setattr(headless, "_server_cookie", lambda pid: None)
        monkeypatch.setattr(
            headless.shutil, "which", lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None
        )
        monkeypatch.setattr(headless, "_wait_for_socket", lambda d, timeout=3.0, proc=None: True)
        spawned: list[str] = []

        class _FakeProc:
            def terminate(self) -> None:
                pass

            def poll(self) -> None:
                return None

            def wait(self, timeout: float = 2) -> int:
                return 0

        def _fake_popen(argv: list[str], *a: Any, **k: Any) -> _FakeProc:
            # Deterministic, no sleep: the barrier above releases all four
            # workers at once so they contend for the init lock; the first
            # spawns and records its display (env + /proc-scan state), the
            # rest reuse it.  Either order of lock acquisition gives one
            # spawn and one agreed display.
            assert headless._XVFB_INIT_LOCK.locked(), "spawn must hold the init lock"
            spawned.append(argv[1])
            spawned_displays.append(argv[1])
            return _FakeProc()

        monkeypatch.setattr(headless.subprocess, "Popen", _fake_popen)
        results: list[str | None] = []
        barrier = threading.Barrier(4)

        def _worker() -> None:
            barrier.wait()
            results.append(ensure_xvfb())

        threads = [threading.Thread(target=_worker, daemon=True) for _ in range(4)]
        for t in threads:
            t.start()
        join_all(threads)
        assert len(results) == 4 and all(r is not None for r in results)
        assert len(set(results)) == 1  # all callers agree on one display
        assert len(spawned) == 1  # exactly one Xvfb was started


class TestWaitForSocket:
    def _clock(self, monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, float], list[float]]:
        """Drive ``_wait_for_socket`` from a clock that advances only in sleep.

        A spin that never sleeps trips the call cap instead of hanging the
        suite. Wall-clock bounds (``< 1.0`` / ``>= 0.25``) pass on a loaded
        host whether or not the timeout was actually consumed.
        """
        from types import SimpleNamespace

        from rebrew import headless

        clock = {"t": 0.0}
        sleeps: list[float] = []
        calls = {"n": 0}

        def _monotonic() -> float:
            calls["n"] += 1
            if calls["n"] > 10_000:
                raise AssertionError("wait loop ignored its deadline")
            return clock["t"]

        def _sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock["t"] += seconds

        monkeypatch.setattr(headless, "time", SimpleNamespace(monotonic=_monotonic, sleep=_sleep))
        return clock, sleeps

    def test_bails_early_when_proc_dies(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A server that exits during startup must fail fast (bad args burn
        the whole timeout otherwise — the screen-argv bug cost 3 s per
        compile before this check)."""
        from rebrew import headless

        monkeypatch.setattr(headless, "_XVFB_SOCKET_DIR", tmp_path)  # socket never appears
        clock, sleeps = self._clock(monkeypatch)

        class DeadProc:
            def poll(self) -> int:
                return 1

        assert headless._wait_for_socket(":90", timeout=5.0, proc=DeadProc()) is False
        assert sleeps == []
        assert clock["t"] == 0.0

    def test_waits_full_timeout_when_proc_alive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew import headless

        monkeypatch.setattr(headless, "_XVFB_SOCKET_DIR", tmp_path)
        clock, sleeps = self._clock(monkeypatch)

        class AliveProc:
            def poll(self) -> None:
                return None

        assert headless._wait_for_socket(":90", timeout=0.3, proc=AliveProc()) is False
        assert sleeps
        assert clock["t"] >= 0.3

    def test_injected_clock_and_sleep_drive_the_loop(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The loop takes its time from the injected seam, not from time.sleep.

        A caller replaying a startup sequence passes both, so the wait costs
        no real time and lands on the same result on any host.
        """
        from rebrew import headless

        clock = {"t": 0.0}
        sleeps: list[float] = []

        def _monotonic() -> float:
            return clock["t"]

        def _sleep(seconds: float) -> None:
            sleeps.append(seconds)
            clock["t"] += seconds

        monkeypatch.setattr(headless.time, "sleep", lambda _s: pytest.fail("real sleep used"))
        monkeypatch.setattr(headless, "_XVFB_SOCKET_DIR", tmp_path)  # socket never appears

        class AliveProc:
            def poll(self) -> None:
                return None

        assert (
            headless._wait_for_socket(
                ":90", timeout=0.3, proc=AliveProc(), clock=_monotonic, sleep=_sleep
            )
            is False
        )
        assert sleeps
        assert clock["t"] >= 0.3

    def test_injected_clock_sees_the_socket_appear(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew import headless

        sock_dir = tmp_path
        monkeypatch.setattr(headless, "_XVFB_SOCKET_DIR", sock_dir)
        (sock_dir / "X90").touch()
        sleeps: list[float] = []
        assert (
            headless._wait_for_socket(":90", timeout=3.0, clock=lambda: 0.0, sleep=sleeps.append)
            is True
        )
        assert sleeps == []


class TestXvfbCookieFor:
    """The cookie/display pair is published under ``_XVFB_INIT_LOCK``."""

    def test_cookie_only_for_the_recorded_display(self, monkeypatch) -> None:
        from rebrew import headless

        monkeypatch.setenv(headless.XVFB_DISPLAY_ENV, ":99")
        monkeypatch.setenv("XAUTHORITY", "/run/cookie-99")
        assert headless.xvfb_cookie_for(":99") == "/run/cookie-99"
        assert headless.xvfb_cookie_for(":77") == ""

    def test_reader_cannot_see_a_half_published_pair(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A compile worker must not pair a new cookie with the old display.

        The publisher writes ``XAUTHORITY`` and then the display as two separate
        ``os.environ`` stores.  A reader that does not take the lock can land
        between them and hand wine the previous server's cookie for the display
        it was just given.  The writer here parks in exactly that window; the
        reader must block until both stores are done.
        """
        from rebrew import headless

        monkeypatch.setenv(headless.XVFB_DISPLAY_ENV, ":77")
        monkeypatch.setenv("XAUTHORITY", "/run/cookie-77")
        in_window = threading.Event()
        proceed = threading.Event()
        observed: list[str] = []

        def publish() -> None:
            with headless._XVFB_INIT_LOCK:
                os.environ["XAUTHORITY"] = "/run/cookie-99"
                in_window.set()  # cookie written, display still says :77
                proceed.wait(timeout=5.0)
                os.environ[headless.XVFB_DISPLAY_ENV] = ":99"

        writer = threading.Thread(target=publish, daemon=True)
        writer.start()
        try:
            assert in_window.wait(timeout=5.0)
            reader = threading.Thread(
                target=lambda: observed.append(headless.xvfb_cookie_for(":99")), daemon=True
            )
            reader.start()
            # The reader is parked on the lock, so nothing is observed yet.
            reader.join(timeout=0.5)
            assert observed == []
            proceed.set()
            reader.join(timeout=5.0)
        finally:
            proceed.set()
            writer.join(timeout=5.0)
        assert not writer.is_alive()
        assert observed == ["/run/cookie-99"]
