"""Full-suite worker injection. Subsets, coverage, and collection stay serial."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from pytest_ansi_env import pytest_load_initial_conftests


class _Plugins:
    def __init__(self, present: bool) -> None:
        self.present = present

    def has_plugin(self, name: str) -> bool:
        return self.present and name == "xdist"


def _early(paths: list[str], *, xdist: bool = True) -> Any:
    return SimpleNamespace(
        pluginmanager=_Plugins(xdist),
        known_args_namespace=SimpleNamespace(file_or_dir=paths),
    )


def _quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    monkeypatch.delenv("SLIPCOVER_ENABLED", raising=False)


class TestSuiteWorkers:
    def test_full_suite_injects_auto(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _quiet(monkeypatch)
        args = ["tests/", "-v", "--tb=short"]
        pytest_load_initial_conftests(_early(["tests/"]), None, args)
        assert args[:2] == ["-n", "auto"]

    def test_bare_pytest_injects_auto(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _quiet(monkeypatch)
        args = ["-q"]
        pytest_load_initial_conftests(_early([]), None, args)
        assert args[:2] == ["-n", "auto"]

    def test_file_node_collect_and_coverage_stay_serial(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _quiet(monkeypatch)
        for paths, args in (
            (["tests/test_core.py"], ["tests/test_core.py", "-q"]),
            (["tests/test_core.py::Test::test_one"], ["tests/test_core.py::Test::test_one"]),
            (["tests/metadata"], ["tests/metadata"]),
            (["tests/"], ["tests/", "--collect-only", "-q"]),
            (["tests/"], ["tests/", "--pdb"]),
            (["tests/"], ["tests/", "-n", "2"]),
            (["tests/"], ["tests/", "-nauto"]),
            (["tests/"], ["tests/", "-p", "no:xdist"]),
        ):
            original = list(args)
            pytest_load_initial_conftests(_early(paths), None, args)
            assert args == original, original

        args = ["tests/", "-q"]
        monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw0")
        pytest_load_initial_conftests(_early(["tests/"]), None, args)
        assert args == ["tests/", "-q"]

        monkeypatch.delenv("PYTEST_XDIST_WORKER")
        monkeypatch.setenv("SLIPCOVER_ENABLED", "1")
        args = ["tests/", "-q"]
        pytest_load_initial_conftests(_early(["tests/"]), None, args)
        assert args == ["tests/", "-q"]

        monkeypatch.delenv("SLIPCOVER_ENABLED")
        args = ["tests/", "-q"]
        pytest_load_initial_conftests(_early(["tests/"], xdist=False), None, args)
        assert args == ["tests/", "-q"]
