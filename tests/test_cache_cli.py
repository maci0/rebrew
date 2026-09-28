"""Tests for rebrew cache CLI (stats / clear)."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rebrew.cache_cli as cache_cli

runner = CliRunner()


def _patch_cfg(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    monkeypatch.setattr(
        cache_cli,
        "require_config",
        lambda target=None, json_mode=False: SimpleNamespace(root=root),
    )


def _clearable_cache(
    monkeypatch: pytest.MonkeyPatch, root: Path, count: int, cleared: list[str]
) -> None:
    """Point the CLI at a populated cache whose clears are recorded in *cleared*."""
    (root / ".rebrew" / "compile_cache").mkdir(parents=True)
    _patch_cfg(monkeypatch, root)
    monkeypatch.setattr(
        cache_cli,
        "get_compile_cache",
        lambda _root, backend="diskcache", size_limit=0: SimpleNamespace(
            count=count,
            clear=lambda: cleared.append("clear"),
            close=lambda: None,
        ),
    )


class TestStats:
    def test_no_cache_dir_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_cfg(monkeypatch, tmp_path)
        r = runner.invoke(cache_cli.app, ["stats", "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        # The absent path carries the same key set as the present one, so a
        # consumer indexes one shape either way.
        assert payload == {
            "exists": False,
            "backend": "diskcache",
            "cache_dir": str(tmp_path / ".rebrew" / "compile_cache"),
            "entries": 0,
            "volume_bytes": 0,
            "volume_mib": 0,
            "size_limit_mib": round(cache_cli.DEFAULT_CACHE_SIZE_LIMIT_MIB, 2),
            "session_hits": 0,
            "session_misses": 0,
            "session_hit_rate_pct": 0.0,
        }

    def test_absent_and_present_payloads_share_a_key_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The parity the absent branch claims, asserted against the real one.

        The absent payload is a hand-written dict, so it drifted from the
        backend's ``stats()`` once (``volume_bytes`` and the ``session_*``
        counters were missing).  Comparing the key sets fails on the next
        drift instead of waiting for a consumer's ``KeyError``.
        """
        (tmp_path / ".rebrew" / "compile_cache").mkdir(parents=True)
        _patch_cfg(monkeypatch, tmp_path)

        def fake_cache(
            _root: Path, backend: str = "diskcache", size_limit: int = 0
        ) -> SimpleNamespace:
            return SimpleNamespace(
                stats=lambda: {
                    "entries": 1,
                    "volume_bytes": 2,
                    "volume_mib": 0.0,
                    "size_limit_mib": 100.0,
                    "session_hits": 0,
                    "session_misses": 0,
                    "session_hit_rate_pct": 0.0,
                },
                close=lambda: None,
            )

        monkeypatch.setattr(cache_cli, "get_compile_cache", fake_cache)
        present = json.loads(
            runner.invoke(cache_cli.app, ["stats", "--json"]).stdout,
        )

        (tmp_path / ".rebrew" / "compile_cache").rmdir()
        absent = json.loads(runner.invoke(cache_cli.app, ["stats", "--json"]).stdout)

        assert set(absent) == set(present)

    def test_no_cache_dir_human(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_cfg(monkeypatch, tmp_path)
        r = runner.invoke(cache_cli.app, ["stats"])
        assert r.exit_code == 0
        assert "No compile cache found (not yet created)." in r.output

    def test_existing_cache_reports(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / ".rebrew" / "compile_cache").mkdir(parents=True)
        _patch_cfg(monkeypatch, tmp_path)
        stats_called: list[bool] = []
        stats_payload: dict[str, object] = {
            "entries": 3,
            "volume_mib": 1.5,
            "size_limit_mib": 100,
            "session_hits": 2,
            "session_misses": 1,
            "session_hit_rate_pct": 66.7,
        }

        def fake_stats() -> dict[str, object]:
            stats_called.append(True)
            return stats_payload

        def fake_cache(
            _root: Path, backend: str = "diskcache", size_limit: int = 0
        ) -> SimpleNamespace:
            return SimpleNamespace(
                stats=fake_stats,
                close=lambda: None,
            )

        monkeypatch.setattr(cache_cli, "get_compile_cache", fake_cache)
        r = runner.invoke(cache_cli.app, ["stats"])
        assert r.exit_code == 0
        assert stats_called == [True]
        # Every field the fake reports has to reach the rendered table; the
        # call assertion above alone would pass with an empty body.
        assert "diskcache" in r.output
        assert "Entries:" in r.output
        assert "1.5 MiB" in r.output
        assert "100 MiB" in r.output
        assert "2 hits, 1 misses" in r.output
        assert "66.7" in r.output

    def test_backend_without_session_counters_still_reports(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A shared store cannot attribute per-process lookups; omit, don't fail.

        ``CacheBackend.stats`` makes the ``session_*`` keys optional, so a
        backend that leaves them out prints its size instead of dying on a
        ``KeyError`` the caller cannot catch.
        """
        (tmp_path / ".rebrew" / "compile_cache").mkdir(parents=True)
        _patch_cfg(monkeypatch, tmp_path)

        def fake_cache(
            _root: Path, backend: str = "diskcache", size_limit: int = 0
        ) -> SimpleNamespace:
            return SimpleNamespace(
                stats=lambda: {"entries": 7, "volume_mib": 2.0, "size_limit_mib": 100},
                close=lambda: None,
            )

        monkeypatch.setattr(cache_cli, "get_compile_cache", fake_cache)
        r = runner.invoke(cache_cli.app, ["stats"])
        assert r.exit_code == 0
        assert "7" in r.output
        assert "no lookups this session" in r.output


class TestClear:
    def test_no_cache_dir_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch_cfg(monkeypatch, tmp_path)
        r = runner.invoke(cache_cli.app, ["clear", "--json"])
        assert r.exit_code == 0
        payload = json.loads(r.stdout)
        # cache_dir / backend are the same fields the clearing path prints,
        # so a consumer reads one shape whether or not there was anything to
        # clear.
        assert payload == {
            "cleared": 0,
            "cache_dir": str(tmp_path / ".rebrew" / "compile_cache"),
            "backend": "diskcache",
            "message": "No compile cache found",
        }

    def test_force_clears_without_prompt(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cleared: list[str] = []
        _clearable_cache(monkeypatch, tmp_path, 4, cleared)
        r = runner.invoke(cache_cli.app, ["clear", "--force"])
        assert r.exit_code == 0
        assert cleared == ["clear"]

    def test_confirmation_prompt_clears(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cleared: list[str] = []
        _clearable_cache(monkeypatch, tmp_path, 2, cleared)
        r = runner.invoke(cache_cli.app, ["clear"], input="y\n")
        assert r.exit_code == 0
        assert cleared == ["clear"]
        # The question is a prompt, not data: it belongs on stderr so
        # `cache clear > log` still shows it on the terminal.
        assert "cached compile results" in r.stderr
        assert "cached compile results" not in r.stdout

    def test_declined_confirmation_clears_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cleared: list[str] = []
        _clearable_cache(monkeypatch, tmp_path, 2, cleared)
        r = runner.invoke(cache_cli.app, ["clear"], input="n\n")
        assert r.exit_code != 0
        assert cleared == []
        assert "cached compile results" in r.stderr
        assert "cached compile results" not in r.stdout

    def test_clear_help_does_not_claim_target_selects_a_root(self) -> None:
        r = runner.invoke(cache_cli.app, ["--help"])
        assert r.exit_code == 0
        assert "specific project root" not in r.output
        assert "cache clear --force" in r.output
