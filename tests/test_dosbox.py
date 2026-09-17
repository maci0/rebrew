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
