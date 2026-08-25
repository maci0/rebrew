"""Tests for rebrew.headless — persistent Xvfb management for headless wine."""

import os
import threading
import time
from pathlib import Path
from typing import Any

from rebrew.headless import (
    _display_alive,
    _pick_free_display,
    ensure_xvfb,
)


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
    def test_reuses_env_display_when_alive(self, monkeypatch) -> None:
        from rebrew import headless

        # A stale REBREW_XVFB_DISPLAY (socket present, no live Xvfb process)
        # must NOT be reused — only a process-backed display qualifies
        # (infra-review F5).
        monkeypatch.setattr(headless, "_display_alive", lambda d: d == ":99")
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {":99": 1234})
        monkeypatch.setenv("REBREW_XVFB_DISPLAY", ":99")
        assert ensure_xvfb() == ":99"

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

    def test_reuses_current_display_when_xvfb(self, monkeypatch) -> None:
        """DISPLAY owned by an Xvfb (already headless) is reused as-is."""
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {":77": 1234})
        monkeypatch.setenv("DISPLAY", ":77")
        assert ensure_xvfb() == ":77"

    def test_reuses_orphan_xvfb(self, monkeypatch) -> None:
        """A live Xvfb left by a prior run is reused (lowest display)."""
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.setattr(headless, "_running_xvfb_displays", lambda: {":99": 1, ":77": 2})
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
        assert spawned[0][2:] == [
            "-screen",
            "0",
            "1280x1024x24",
            "-nolisten",
            "tcp",
        ]  # screen geometry as separate argv tokens — a single joined
        # "-screen 0 1280x1024x24" string makes Xvfb fail to start and
        # silently degrades every wine compile to the 3 s xvfb-run wrapper.
        # The display is not pinned: in the full suite the process may
        # already own a server on :90, so the spawn lands on the next free.
        assert spawned[0][1] == result
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

    def test_concurrent_callers_spawn_one_server(self, monkeypatch) -> None:
        """Parallel compile workers calling ensure_xvfb must not double-spawn.

        Without the init lock, two threads can both pass the env/orphan
        checks before either records its display, pick the same free
        display, and spawn two Xvfb processes (one dies with "server
        already active").
        """
        from rebrew import headless

        monkeypatch.delenv("REBREW_XVFB_DISPLAY", raising=False)
        monkeypatch.delenv("DISPLAY", raising=False)
        # Stateful /proc scan: once a worker spawns Xvfb, later workers must
        # see the live process (the env-display reuse now requires process
        # liveness, not just a socket — infra-review F5).
        spawned_displays: list[str] = []

        def _fake_running() -> dict[str, int]:
            return dict.fromkeys(spawned_displays, 1)

        monkeypatch.setattr(headless, "_running_xvfb_displays", _fake_running)
        monkeypatch.setattr(headless, "_display_alive", lambda d: True)
        monkeypatch.setattr(
            headless.shutil, "which", lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None
        )
        monkeypatch.setattr(headless, "_wait_for_socket", lambda d, timeout=3.0, proc=None: True)
        spawned: list[str] = []

        class _FakeProc:
            def terminate(self) -> None:
                pass

            def wait(self, timeout: float = 2) -> int:
                return 0

        def _fake_popen(argv: list[str], *a: Any, **k: Any) -> _FakeProc:
            # Yield inside the spawn window: without the init lock every
            # worker reaches this point before any of them records its
            # display, and the spawn count explodes.
            time.sleep(0.002)
            spawned.append(argv[1])
            spawned_displays.append(argv[1])
            return _FakeProc()

        monkeypatch.setattr(headless.subprocess, "Popen", _fake_popen)
        results: list[str | None] = []
        barrier = threading.Barrier(4)

        def _worker() -> None:
            barrier.wait()
            results.append(ensure_xvfb())

        threads = [threading.Thread(target=_worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 4 and all(r is not None for r in results)
        assert len(set(results)) == 1  # all callers agree on one display
        assert len(spawned) == 1  # exactly one Xvfb was started


class TestWaitForSocket:
    def test_bails_early_when_proc_dies(self, tmp_path: Path, monkeypatch) -> None:
        """A server that exits during startup must fail fast (bad args burn
        the whole timeout otherwise — the screen-argv bug cost 3 s per
        compile before this check)."""
        import time

        from rebrew import headless

        monkeypatch.setattr(headless, "_XVFB_SOCKET_DIR", tmp_path)  # socket never appears

        class DeadProc:
            def poll(self) -> int:
                return 1

        t0 = time.monotonic()
        assert headless._wait_for_socket(":90", timeout=5.0, proc=DeadProc()) is False
        assert time.monotonic() - t0 < 1.0  # bailed immediately, not after 5 s

    def test_waits_full_timeout_when_proc_alive(self, tmp_path: Path, monkeypatch) -> None:
        import time

        from rebrew import headless

        monkeypatch.setattr(headless, "_XVFB_SOCKET_DIR", tmp_path)

        class AliveProc:
            def poll(self):
                return None

        t0 = time.monotonic()
        assert headless._wait_for_socket(":90", timeout=0.3, proc=AliveProc()) is False
        assert time.monotonic() - t0 >= 0.25  # waited out the timeout
