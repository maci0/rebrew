"""A stand-in ``docker`` on PATH whose images exist and whose ``run`` exits a chosen status."""

from __future__ import annotations

import os
lazy from pathlib import Path

import pytest

import rebrew.compiler.toolchain as toolchain

#: The daemon-style line the stand-in prints on stderr for a status other than 1.
DAEMON_LINE = "docker: Error response from daemon: failed to create task on host build-7"

#: The diagnostic the stand-in prints on stdout, as a compiler that ran would.
DIAGNOSTIC = "fcn.c(3) : error C2065: 'nope' : undeclared identifier"


def install_fake_runtime(monkeypatch: pytest.MonkeyPatch, bin_dir: Path, status: int) -> None:
    """Put the stand-in first on PATH; ``run`` prints :data:`DIAGNOSTIC` and exits *status*.

    Child processes inherit it through the environment.  The runtime memos of this
    process start empty and are restored after the test.
    """
    bin_dir.mkdir()
    runtime = bin_dir / "docker"
    runtime.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = run ]; then\n'
        '  echo "$FAKE_RUN_DIAGNOSTIC"\n'
        '  [ -n "$FAKE_RUN_STDERR" ] && echo "$FAKE_RUN_STDERR" >&2\n'
        '  exit "$FAKE_RUN_STATUS"\n'
        "fi\n"
        'if [ "$1" = image ] && [ "$3" = --format ]; then\n'
        "  echo sha256:" + "a" * 64 + "\n"
        "fi\n"
        "exit 0\n"
    )
    runtime.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
    monkeypatch.delenv("REBREW_CONTAINER_RUNTIME", raising=False)
    monkeypatch.setenv("FAKE_RUN_STATUS", str(status))
    monkeypatch.setenv("FAKE_RUN_DIAGNOSTIC", DIAGNOSTIC)
    monkeypatch.setenv("FAKE_RUN_STDERR", DAEMON_LINE if status != 1 else "")
    monkeypatch.setattr(toolchain, "_docker_available_cache", None)
    monkeypatch.setattr(toolchain, "_runtime_availability", set())
    monkeypatch.setattr(toolchain, "_image_presence", {})
    monkeypatch.setattr(toolchain, "_toolchain_digest_cache", {})
