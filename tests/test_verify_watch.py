"""Tests for rebrew verify --watch (multi-file watch mode)."""

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import rebrew.verify as verify_mod


class TestWatchFiles:
    def test_retests_on_change(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.utils import watch_files

        a = tmp_path / "a.c"
        b = tmp_path / "b.c"
        a.write_text("1", encoding="utf-8")
        b.write_text("1", encoding="utf-8")
        calls: list[str] = []

        def fake_sleep(_seconds: float) -> None:
            if not calls:
                os.utime(b, ns=(1_800_000_000_000_000_000, 1_800_000_001_000_000_000))
            else:
                raise KeyboardInterrupt

        monkeypatch.setattr("rebrew.utils.time.sleep", fake_sleep)
        watch_files([a, b], lambda: calls.append("retest"))
        assert calls == ["retest"]

    def test_no_change_no_retest(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.utils import watch_files

        a = tmp_path / "a.c"
        a.write_text("1", encoding="utf-8")
        calls: list[str] = []
        monkeypatch.setattr(
            "rebrew.utils.time.sleep", lambda _s: (_ for _ in ()).throw(KeyboardInterrupt())
        )
        watch_files([a], lambda: calls.append("retest"))
        assert calls == []

    def test_missing_file_tolerated(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.utils import watch_files

        a = tmp_path / "a.c"  # does not exist yet
        calls: list[str] = []
        created = False

        def fake_sleep(_seconds: float) -> None:
            nonlocal created
            if not created:
                a.write_text("1", encoding="utf-8")
                created = True
            elif not calls:
                os.utime(a, ns=(1_800_000_000_000_000_000, 1_800_000_001_000_000_000))
            else:
                raise KeyboardInterrupt

        monkeypatch.setattr("rebrew.utils.time.sleep", fake_sleep)
        watch_files([a], lambda: calls.append("retest"))
        assert calls == ["retest"]

    def test_failed_retest_does_not_stop(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.utils import watch_files

        a = tmp_path / "a.c"
        a.write_text("1", encoding="utf-8")
        calls: list[str] = []

        def fake_sleep(_seconds: float) -> None:
            if not calls:
                os.utime(a, ns=(1_800_000_000_000_000_000, 1_800_000_001_000_000_000))
            elif calls == ["fail"]:
                os.utime(a, ns=(1_800_000_000_000_000_000, 1_800_000_002_000_000_000))
            else:
                raise KeyboardInterrupt

        def retest() -> None:
            if not calls:
                calls.append("fail")
                raise RuntimeError("compile broke")
            calls.append("retest")

        monkeypatch.setattr("rebrew.utils.time.sleep", fake_sleep)
        watch_files([a], retest)
        assert calls == ["fail", "retest"]

    def test_path_provider_picks_up_new_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A file created DURING the session (path_provider re-resolves the
        set every poll) must be watched — the old code captured the list
        once at startup and silently stopped covering new files."""
        from rebrew.utils import watch_files

        a = tmp_path / "a.c"
        a.write_text("1", encoding="utf-8")
        new_file = tmp_path / "new.c"  # created mid-session
        calls: list[str] = []

        def fake_sleep(_seconds: float) -> None:
            if not new_file.exists():
                new_file.write_text("1", encoding="utf-8")  # appears now
                os.utime(new_file, ns=(1_800_000_000_000_000_000, 1_800_000_001_000_000_000))
            elif not calls:
                # Touch the NEW file — only reachable if the provider added it.
                os.utime(new_file, ns=(1_800_000_000_000_000_000, 1_800_000_002_000_000_000))
            else:
                raise KeyboardInterrupt

        monkeypatch.setattr("rebrew.utils.time.sleep", fake_sleep)
        watch_files(
            [a],
            lambda: calls.append("retest"),
            path_provider=lambda: [a, new_file],
        )
        # The new file's mtime change triggered a retest — provider works.
        assert calls == ["retest"]

    def test_injected_sleep_drives_the_poll(self, tmp_path: Path) -> None:
        """The poll interval is spent through the injected sleeper.

        Passing it lets a replay step a virtual clock instead of waiting on
        wall-clock time, so the same edit sequence is observed every time.
        """
        from rebrew.utils import watch_files

        a = tmp_path / "a.c"
        a.write_text("1", encoding="utf-8")
        calls: list[str] = []
        slept: list[float] = []

        def fake_sleep(seconds: float) -> None:
            slept.append(seconds)
            if not calls:
                os.utime(a, ns=(1_800_000_000_000_000_000, 1_800_000_001_000_000_000))
            else:
                raise KeyboardInterrupt

        watch_files([a], lambda: calls.append("retest"), interval=0.25, sleep=fake_sleep)
        assert calls == ["retest"]
        assert slept and set(slept) == {0.25}


class TestVerifyWatchCli:
    def test_watch_dispatches_to_watch_files(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, Any] = {}
        monkeypatch.setattr(
            verify_mod,
            "require_config",
            lambda target=None, json_mode=False, root=None: SimpleNamespace(
                reversed_dir=Path("/tmp"), default_jobs=4, db_dir=Path("/tmp")
            ),
        )
        discovered: list[Path] = [Path("/tmp/a.c"), Path("/tmp/b.c")]
        monkeypatch.setattr("rebrew.sources.iter_sources", lambda _d, _c: list(discovered))

        def fake_watch(paths: list[Path], retest: object, **kwargs: object) -> None:
            seen["paths"] = paths
            seen["retest"] = retest
            seen["kwargs"] = kwargs

        monkeypatch.setattr("rebrew.utils.watch_files", fake_watch)
        # Note: typer's callback wrapper misbinds partial keyword sets on direct
        # calls, so every parameter must be passed explicitly.
        verify_mod.main(
            root=None,
            jobs=None,
            output_path=None,
            summary=False,
            diff_mode=False,
            full=False,
            context=None,
            json_output=False,
            dry_run=False,
            watch=True,
            target=None,
        )
        assert seen["paths"] == [Path("/tmp/a.c"), Path("/tmp/b.c")]
        assert callable(seen["retest"])
        # The provider, not the list captured at startup: a file added after
        # the watch began must still be covered.
        kwargs = seen["kwargs"]
        assert callable(kwargs["path_provider"])
        discovered.append(Path("/tmp/c.c"))
        assert kwargs["path_provider"]() == discovered
