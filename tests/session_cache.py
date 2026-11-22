"""Results a test session builds once and every xdist worker reuses.

A module- or session-scoped fixture runs once per xdist worker, so a fixture
that analyses a binary repeated that analysis on every worker that ran one of
the module's tests. :func:`build_once` builds a directory once per session:
the first worker to ask builds it under an exclusive ``fcntl`` lock and the
others wait for it. Callers copy before they write; nothing here enforces that.
"""

from __future__ import annotations

import fcntl
import json
import os
import shutil
from typing import Any
lazy from collections.abc import Callable
lazy from pathlib import Path

import pytest

_DONE = "session-cache.json"


def shared_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """The session's directory every worker sees.

    Under xdist each worker's base temp is ``<session>/popen-gwN``, so the
    parent belongs to this session alone; without xdist it is the base temp.
    """
    base = tmp_path_factory.getbasetemp()
    root = (base.parent if os.environ.get("PYTEST_XDIST_WORKER") else base) / "session-cache"
    root.mkdir(exist_ok=True)
    return root


def build_once(
    tmp_path_factory: pytest.TempPathFactory, name: str, build: Callable[[Path], Any]
) -> tuple[Path, Any]:
    """``(directory, build(directory))``, built by the first caller in the session.

    *build* fills the empty *directory* in place, since its result may name
    paths inside it, and returns a JSON value. A build that raises leaves no
    result: the directory is removed and the next caller builds again.
    """
    root = shared_root(tmp_path_factory)
    directory = root / name
    done = root / f"{name}.{_DONE}"
    with (root / f"{name}.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if done.is_file():
            return directory, json.loads(done.read_text(encoding="utf-8"))
        if directory.exists():  # a build that died without its result
            shutil.rmtree(directory)
        directory.mkdir()
        try:
            value = build(directory)
        except BaseException:
            shutil.rmtree(directory)
            raise
        done.write_text(json.dumps(value), encoding="utf-8")
        return directory, value
