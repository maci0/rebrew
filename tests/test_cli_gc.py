"""The CLI entry point freezes its import-time object graph exactly once."""

from __future__ import annotations

import gc

import pytest


def test_startup_freeze_is_one_shot(monkeypatch: pytest.MonkeyPatch) -> None:
    """A second call must not freeze the command's own allocations too.

    Frozen objects are never rescanned by a full collection, which is the
    point: the typer/rich/registry graph is live for the whole process. The
    counter is the gate, not a duration.
    """
    from rebrew.app import main as cli_main

    monkeypatch.setattr(cli_main, "_STARTUP_GC_FROZEN", False)
    before = gc.get_freeze_count()
    try:
        cli_main._freeze_startup_objects()
        after_first = gc.get_freeze_count()
        assert after_first > before
        cli_main._freeze_startup_objects()
        assert gc.get_freeze_count() == after_first
    finally:
        gc.unfreeze()


def test_startup_freeze_does_not_run_a_preliminary_collection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Freeze once without requesting a preliminary collection."""
    from rebrew.app import main as cli_main

    calls: list[str] = []
    monkeypatch.setattr(cli_main, "_STARTUP_GC_FROZEN", False)
    monkeypatch.setattr(gc, "collect", lambda: calls.append("collect"))
    monkeypatch.setattr(gc, "freeze", lambda: calls.append("freeze"))
    cli_main._freeze_startup_objects()
    cli_main._freeze_startup_objects()
    assert calls == ["freeze"]
