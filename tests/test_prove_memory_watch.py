"""Tests for prove watched-VA memory comparison (#25.2).

The comparison loop is exercised two ways:
1. A minimal fake ``claripy`` module (no dependency): with concrete int
   values, ``BVV`` is identity, ``Or`` is ``any``, and the solver's
   satisfiability is simply whether the last diff term is true.
2. Real claripy + Z3 when installed (see TestCompareStatePairsRealClaripy).
"""

import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import rebrew.prove as prove_mod

has_claripy = importlib.util.find_spec("claripy") is not None


def _install_fake_claripy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``import claripy`` inside rebrew.prove resolve to a minimal fake."""

    class _Solver:
        def __init__(self) -> None:
            self.constraints: list[bool] = []

        def add(self, expr: bool) -> None:
            self.constraints.append(expr)

        def satisfiable(self) -> bool:
            return bool(self.constraints[-1])

        def eval(self, e: Any, n: int = 1) -> tuple[Any, ...]:
            """claripy 9.x: eval returns a tuple of up to n concrete values."""
            return tuple(e for _ in range(n))

        def batch_eval(self, exprs: list[Any], n: int = 1) -> list[tuple[Any, ...]]:
            """Return one solution tuple holding each expr's concrete value."""
            return [tuple(exprs)]

    fake = types.ModuleType("claripy")
    fake.BVV = lambda value, bits=0: value
    fake.BoolV = lambda value: bool(value)
    fake.Or = lambda *terms: any(terms)
    fake.Solver = _Solver
    monkeypatch.setitem(sys.modules, "claripy", fake)


def _make_state(eax: int, edx: int, mem: dict[int, int], mapped: set[int]) -> Any:
    """Build a mock angr state with concrete registers and a scripted memory."""

    class _Mem:
        def __init__(self) -> None:
            self.mem = mem
            self.mapped = mapped

        def load(self, va: int, size: int) -> int:
            if va not in self.mapped:
                raise RuntimeError("unmapped")
            return self.mem[va]

    state = SimpleNamespace()
    state.regs = SimpleNamespace(eax=eax, edx=edx)
    state.solver = SimpleNamespace(constraints=[])
    state.memory = _Mem()
    return state


class TestMemValue:
    def test_mapped_returns_value(self) -> None:
        s = _make_state(1, 0, {0x1000: 7}, {0x1000})
        assert prove_mod._mem_value(s, 0x1000) == 7

    def test_unmapped_returns_none(self) -> None:
        s = _make_state(1, 0, {}, set())
        assert prove_mod._mem_value(s, 0x1000) is None


class TestCompareStatePairs:
    def test_memory_match_proven(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_claripy(monkeypatch)
        orig = _make_state(eax=42, edx=0, mem={0x1000: 5}, mapped={0x1000})
        comp = _make_state(eax=42, edx=0, mem={0x1000: 5}, mapped={0x1000})
        proven, msg = prove_mod._compare_state_pairs([orig], [comp], False, [0x1000])
        assert proven
        assert "mem(1 VA)" in msg

    def test_memory_differs_not_proven(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_claripy(monkeypatch)
        orig = _make_state(eax=42, edx=0, mem={0x1000: 5}, mapped={0x1000})
        comp = _make_state(eax=42, edx=0, mem={0x1000: 9}, mapped={0x1000})
        proven, msg = prove_mod._compare_state_pairs([orig], [comp], False, [0x1000])
        assert not proven
        assert "mem(1 VA)" in msg
        # Registers agree, so the counterexample pinpoints the differing VA
        assert "mem[0x1000]=5 vs 9" in msg

    def test_unmapped_both_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_claripy(monkeypatch)
        orig = _make_state(eax=42, edx=0, mem={}, mapped=set())
        comp = _make_state(eax=42, edx=0, mem={}, mapped=set())
        proven, _msg = prove_mod._compare_state_pairs([orig], [comp], False, [0x2000])
        assert proven  # nothing to compare — no difference

    def test_unmapped_one_side_is_difference(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_claripy(monkeypatch)
        orig = _make_state(eax=42, edx=0, mem={0x1000: 5}, mapped={0x1000})
        comp = _make_state(eax=42, edx=0, mem={}, mapped=set())
        proven, msg = prove_mod._compare_state_pairs([orig], [comp], False, [0x1000])
        assert not proven
        assert "mapped on one side only" in msg

    def test_registers_still_checked_with_memory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_claripy(monkeypatch)
        orig = _make_state(eax=42, edx=0, mem={0x1000: 5}, mapped={0x1000})
        comp = _make_state(eax=99, edx=0, mem={0x1000: 5}, mapped={0x1000})
        proven, msg = prove_mod._compare_state_pairs([orig], [comp], False, [0x1000])
        assert not proven
        assert "EAX" in msg
        assert "EAX=42 vs 99" in msg  # counterexample detail from the model

    def test_edx_counterexample_in_message(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_claripy(monkeypatch)
        orig = _make_state(eax=42, edx=7, mem={}, mapped=set())
        comp = _make_state(eax=42, edx=99, mem={}, mapped=set())
        proven, msg = prove_mod._compare_state_pairs([orig], [comp], True, [])
        assert not proven
        assert "EAX+EDX" in msg
        assert "EDX=7 vs 99" in msg

    def test_no_watched_vas_message_unchanged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_claripy(monkeypatch)
        orig = _make_state(eax=42, edx=0, mem={}, mapped=set())
        comp = _make_state(eax=42, edx=0, mem={}, mapped=set())
        proven, msg = prove_mod._compare_state_pairs([orig], [comp], False, [])
        assert proven
        assert "mem(" not in msg  # no memory label when nothing is watched


class TestResolveWatchedDir32:
    def _patch_sources(self, monkeypatch: pytest.MonkeyPatch, name_to_va: dict[str, int]) -> None:
        monkeypatch.setattr(prove_mod, "build_name_to_va", lambda cfg: name_to_va)

        def fake_relocs(_path: str | Path, _symbol: str) -> list[Any]:
            return [
                SimpleNamespace(offset=10, type=0x06, symbol="_g_data"),  # DIR32
                SimpleNamespace(offset=14, type=0x14, symbol="_g_call"),  # REL32
            ]

        monkeypatch.setattr(prove_mod, "parse_obj_relocs_full", fake_relocs)

    def test_resolves_underscore_symbol(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """MSVC '_g_data' resolves to watched VA via underscore-stripped lookup."""
        self._patch_sources(monkeypatch, {"g_data": 0x10123456})
        out = prove_mod._resolve_watched_dir32("f.obj", "_f", object(), {0x10123456})
        assert out == {10: 0x10123456}

    def test_ignores_non_dir32_and_unwatched(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_sources(monkeypatch, {"g_data": 0x10123456, "g_other": 0x10222222})
        out = prove_mod._resolve_watched_dir32("f.obj", "_f", object(), {0x10222222})
        assert out == {}  # REL32 at 14 excluded; g_data VA not in watched set

    def test_empty_watched_set_short_circuits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called: list[str] = []

        def boom(_path: str | Path, _symbol: str) -> list[Any]:
            called.append("relocs")
            raise AssertionError("must not be called")

        monkeypatch.setattr(prove_mod, "parse_obj_relocs_full", boom)
        out = prove_mod._resolve_watched_dir32("f.obj", "_f", object(), set())
        assert out == {}
        assert called == []


@pytest.mark.skipif(not has_claripy, reason="claripy not installed")
class TestCompareStatePairsRealClaripy:
    """Exercise _compare_state_pairs against real claripy + Z3 solving."""

    def _make_state(self, eax: int, edx: int, mem: dict[int, int] | None) -> Any:
        import claripy

        if mem is None:
            mem = {}

        class _Mem:
            def load(self, va: int, size: int) -> Any:
                if va not in mem:
                    raise RuntimeError("unmapped")
                return claripy.BVV(mem[va], 32)

        state = SimpleNamespace()
        state.regs = SimpleNamespace(eax=claripy.BVV(eax, 32), edx=claripy.BVV(edx, 32))
        state.solver = SimpleNamespace(constraints=[])
        state.memory = _Mem()
        return state

    def test_memory_match_proven(self) -> None:
        orig = self._make_state(42, 0, {0x1000: 5})
        comp = self._make_state(42, 0, {0x1000: 5})
        proven, msg = prove_mod._compare_state_pairs([orig], [comp], False, [0x1000])
        assert proven
        assert "mem(1 VA)" in msg

    def test_memory_differs_not_proven(self) -> None:
        orig = self._make_state(42, 0, {0x1000: 5})
        comp = self._make_state(42, 0, {0x1000: 9})
        proven, _msg = prove_mod._compare_state_pairs([orig], [comp], False, [0x1000])
        assert not proven

    def test_register_difference_still_rejected(self) -> None:
        orig = self._make_state(42, 0, {0x1000: 5})
        comp = self._make_state(99, 0, {0x1000: 5})  # memory equal, EAX differs
        proven, msg = prove_mod._compare_state_pairs([orig], [comp], False, [0x1000])
        assert not proven
        assert "EAX" in msg

    def test_symbolic_memory_equality(self) -> None:
        """Symbolic watched values that are constrained equal must prove."""
        import claripy

        sym = claripy.BVS("shared", 32)
        orig = self._make_state(42, 0, {})
        comp = self._make_state(42, 0, {})

        class _Mem:
            def load(self, va: int, size: int) -> Any:
                return sym

        orig.memory = _Mem()
        comp.memory = _Mem()
        proven, _msg = prove_mod._compare_state_pairs([orig], [comp], False, [0x1000])
        assert proven  # same symbolic value on both sides — Z3 can't distinguish
