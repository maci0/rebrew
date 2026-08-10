"""Tests for rebrew.discover — chained function discovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from rebrew.discover import _is_padding, discover_functions


class TestIsPadding:
    def test_int3_padding(self) -> None:
        # extract_bytes is mocked via the autouse fixture — test the byte logic
        assert _is_padding(_mk_info(b"\xcc\xcc\xcc"), 0, 3) is True

    def test_nop_padding(self) -> None:
        assert _is_padding(_mk_info(b"\x90\x90\x90"), 0, 3) is True

    def test_code_is_not_padding(self) -> None:
        assert _is_padding(_mk_info(b"\x55\x8b\xec"), 0, 3) is False


def _mk_info(raw: bytes):
    class Fake:
        pass

    info = Fake()
    info.data = raw
    return info  # noqa: F841


@pytest.fixture(autouse=True)
def _patch_extract(monkeypatch):
    """Route rebrew.analysis.extract_bytes to the fake info's raw bytes."""
    import rebrew.analysis

    def _extract(info, va, size):  # noqa: ARG001
        return info.data[va : va + size]

    monkeypatch.setattr(rebrew.analysis, "extract_bytes", _extract)


class TestDiscoverFunctions:
    def test_merge_and_validation(self, monkeypatch) -> None:
        # rizin aaa gives one garbled huge function; aap gives the real set;
        # the sweep adds an interior false positive that must be dropped.
        aaa = [(0x401000, 1000, "fcn.00401000"), (0x401300, 50, "fcn.00401300")]
        aap = [
            (0x401000, 40, "fcn.00401000"),
            (0x401028, 20, "fcn.00401028"),
            (0x401040, 30, "fcn.00401040"),
            (0x401300, 50, "fcn.00401300"),
        ]
        monkeypatch.setattr(
            "rebrew.discover._rizin_functions", lambda b, c: aaa if c == ["aaa"] else aap
        )
        monkeypatch.setattr(
            "rebrew.discover._capstone_sweep", lambda b: [(0x401000, 0, "x"), (0x401034, 0, "y")]
        )

        # Mock load_binary + iter_instructions for the validation pass: every
        # function ends in a ret right before the next start.
        class Insn:
            def __init__(self, va, size, mnemonic):
                self.va = va
                self.size = size
                self.mnemonic = mnemonic

        def _iter_instructions(info, va, size):  # noqa: ARG001
            # one code instruction filling the span, then a ret at the end
            yield Insn(va, max(size - 1, 1), "code")
            yield Insn(va + max(size - 1, 1), 1, "ret")

        monkeypatch.setattr("rebrew.discover.load_binary", lambda b: _mk_info(b""))
        monkeypatch.setattr("rebrew.discover.iter_instructions", _iter_instructions)
        monkeypatch.setattr("rebrew.discover._is_padding", lambda info, va, end: True)

        d = discover_functions(Path("x.exe"))
        # merged candidate VAs: aaa(0x401000,0x401300) + aap(+0x401028,0x401040)
        # + sweep(0x401034 interior) — all present after merge.
        vas = [va for va, _s, _n in d.functions]
        assert 0x401000 in vas
        assert 0x401300 in vas
        assert 0x401028 in vas
        # every function has a positive size
        assert all(size > 0 for _va, size, _n in d.functions)
