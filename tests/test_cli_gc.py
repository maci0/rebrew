"""The CLI entry point freezes its import-time graph once and raises the young GC threshold."""

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


def test_cli_run_collects_young_objects_less_often(monkeypatch: pytest.MonkeyPatch) -> None:
    """The command runs under the raised young threshold; older ones are kept."""
    from rebrew.app import main as cli_main

    seen: list[tuple[int, ...]] = []
    original = gc.get_threshold()
    monkeypatch.setattr(cli_main, "_STARTUP_GC_FROZEN", True)
    monkeypatch.setattr(cli_main, "run_cli", lambda _app: seen.append(gc.get_threshold()))
    try:
        cli_main.main()
    finally:
        gc.set_threshold(*original)
    assert seen == [(cli_main._GC_YOUNG_THRESHOLD, *original[1:])]
