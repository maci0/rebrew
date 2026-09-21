"""Tests for rebrew.dosbox — sandbox lifecycle guarantees.

The auto-created DOSBox sandboxes (msvc16/borland-3.1/delphi-1.0 compile staging)
each hold a compiler tree + staged source; they must be removed at process
exit instead of accumulating one directory per compile under
~/.cache/rebrew/tmp.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from rebrew.dosbox import make_sandbox_dir

_SRC = Path(__file__).resolve().parents[1] / "src"


class TestSandboxLifecycle:
    def test_sandbox_registered_for_exit_removal(self, monkeypatch) -> None:
        """make_sandbox_dir tracks the dir and registers one atexit sweep."""
        import rebrew.dosbox as dosbox

        registered: list[tuple] = []
        monkeypatch.setattr(
            "rebrew.dosbox.atexit.register", lambda fn, *a: registered.append((fn, a))
        )
        # Fresh process state for the once-guard (module may already be armed).
        monkeypatch.setattr(dosbox, "_SANDBOX_ATEXIT_REGISTERED", False)
        monkeypatch.setattr(dosbox, "_SANDBOXES", [])
        monkeypatch.setattr(dosbox, "_SANDBOX_BY_PREFIX", {})
        sandbox = make_sandbox_dir("rebrew-test-sandbox-")
        second = make_sandbox_dir("rebrew-test-sandbox2-")
        assert sandbox.is_dir() and second.is_dir()
        assert len(registered) == 1, "one atexit hook for every sandbox"
        assert [sandbox, second] == dosbox._SANDBOXES
        fn, args = registered[0]
        fn(*args)
        assert not sandbox.exists(), "sandbox must be removed by the exit hook"
        assert not second.exists()
        assert dosbox._SANDBOXES == []
        assert dosbox._SANDBOX_BY_PREFIX == {}

    def test_same_prefix_reuses_sandbox(self, monkeypatch) -> None:
        """Repeated default compiles must not accumulate one dir per call."""
        import rebrew.dosbox as dosbox

        monkeypatch.setattr(dosbox, "_SANDBOX_ATEXIT_REGISTERED", True)
        monkeypatch.setattr(dosbox, "_SANDBOXES", [])
        monkeypatch.setattr(dosbox, "_SANDBOX_BY_PREFIX", {})
        first = make_sandbox_dir("rebrew-test-reuse-")
        second = make_sandbox_dir("rebrew-test-reuse-")
        assert first == second
        assert [first] == dosbox._SANDBOXES
        from rebrew.dosbox import release_sandbox

        release_sandbox(first)
        assert not first.exists()
        assert dosbox._SANDBOXES == []
        assert dosbox._SANDBOX_BY_PREFIX == {}

    def test_concurrent_same_prefix_isolates_per_thread(self, monkeypatch) -> None:
        """Parallel 16-bit compiles must not share one staged tree.

        Reusing a single sandbox across threads raced on ``.OBJ``/``.EXE``
        names and mixed compile outputs.  Each worker gets its own dir;
        same-thread sequential reuse is covered separately.
        """
        import threading
        import time

        import rebrew.dosbox as dosbox

        monkeypatch.setattr(dosbox, "_SANDBOX_ATEXIT_REGISTERED", True)
        monkeypatch.setattr(dosbox, "_SANDBOXES", [])
        monkeypatch.setattr(dosbox, "_SANDBOX_BY_PREFIX", {})
        results: list[Path] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(16)
        hold = threading.Event()
        lock = threading.Lock()

        def _worker() -> None:
            try:
                barrier.wait(timeout=30)
                path = make_sandbox_dir("rebrew-test-concurrent-")
                with lock:
                    results.append(path)
                # Stay alive until the main thread finishes asserting — otherwise
                # a fast worker's death would let a slow peer reap its sandbox.
                hold.wait(timeout=30)
            except BaseException as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(16)]
        for t in threads:
            t.start()
        # Wait until every worker has published a path (still alive via hold).
        deadline = time.monotonic() + 60
        while len(results) < 16 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert errors == []
        assert len(results) == 16
        assert len(set(results)) == 16
        assert set(results) == set(dosbox._SANDBOXES)
        hold.set()
        for t in threads:
            t.join(timeout=60)
        from rebrew.dosbox import release_sandbox

        for path in results:
            release_sandbox(path)
        assert dosbox._SANDBOXES == []
        assert dosbox._SANDBOX_BY_PREFIX == {}

    def test_dead_thread_sandboxes_are_reaped(self, monkeypatch) -> None:
        """Retired pool workers must not leave sandboxes until process exit.

        ``verify --watch`` builds a fresh ThreadPoolExecutor each pass; without
        reaping, each retired thread id kept a full compiler staging dir.
        """
        import threading

        import rebrew.dosbox as dosbox

        monkeypatch.setattr(dosbox, "_SANDBOX_ATEXIT_REGISTERED", True)
        monkeypatch.setattr(dosbox, "_SANDBOXES", [])
        monkeypatch.setattr(dosbox, "_SANDBOX_BY_PREFIX", {})
        orphan: list[Path] = []

        def _worker() -> None:
            orphan.append(make_sandbox_dir("rebrew-test-reap-"))

        t = threading.Thread(target=_worker)
        t.start()
        t.join(timeout=30)
        assert orphan and orphan[0].is_dir()
        assert orphan == dosbox._SANDBOXES
        mine = make_sandbox_dir("rebrew-test-reap-")
        assert not orphan[0].exists()
        assert [mine] == dosbox._SANDBOXES
        assert mine.is_dir()
        from rebrew.dosbox import release_sandbox

        release_sandbox(mine)
        assert dosbox._SANDBOXES == []
        assert dosbox._SANDBOX_BY_PREFIX == {}

    def test_sandbox_gone_after_process_exit(self) -> None:
        """End-to-end: a child process creating a default sandbox leaves no
        directory behind once it exits."""
        code = (
            "from rebrew.dosbox import make_sandbox_dir\n"
            "print(make_sandbox_dir('rebrew-test-exit-'))\n"
        )
        env = {**os.environ, "PYTHONPATH": str(_SRC)}
        r = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
            check=True,
        )
        sandbox = Path(r.stdout.strip())
        assert not sandbox.exists()
