"""test_prove_soundness.py — Soundness regression tests for rebrew.prove.

Covers the prove.py P0 soundness fixes without requiring angr:

1. Timeout fail-closed: ``prove_equivalence`` must never report PROVEN when
   either side's symbolic execution timed out with incomplete path cover.
   Tested by patching ``_run_simulation`` with crafted (states, timed_out)
   pairs and letting the real ``prove_equivalence`` comparison path run.
2. Bounded symbolic copy length: ``_copy_length_or_none`` must return None
   (refuse) for a symbolic length unbounded above the copy cap, and the
   exact/bounded length otherwise.  Tested with real claripy (declared in
   the ``prove`` extra, no angr import needed).
3. Offset-map mismatch: ``prove_equivalence`` must return INCONCLUSIVE when
   original call-site counts and compiled reloc-call counts differ, instead
   of patching the original blob at compiled offsets.
4. Per-call-site stub returns: ``_fingerprint_args`` must distinguish
   distinct symbolic argument formulas and equate identical ones across
   projects (real claripy ASTs).
"""

from __future__ import annotations

import importlib.util
import sys
import types
from typing import Any

import pytest

import rebrew.prove as prove_mod
import rebrew.prove_simprocs as simprocs_mod

has_claripy = importlib.util.find_spec("claripy") is not None


def _install_fake_angr(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """Install a fake ``angr`` module so ``prove_equivalence`` body runs.

    Only the names touched before ``_run_simulation`` matter: ``Project``
    (project construction), ``options`` (state-setup flags), and
    ``SimProcedure`` (the ``SharedReturnStub`` class definition).  Calling
    ``AngrUnavailable`` anywhere means the test setup is incomplete.
    """

    class AngrUnavailable(Exception):
        pass

    def _unavailable(*args: Any, **kwargs: Any) -> Any:
        raise AngrUnavailable("fake angr: unexpected call")

    class _FakeRegs:
        def __setattr__(self, name: str, value: Any) -> None:
            pass

    class _FakeMemory:
        def store(self, *args: Any, **kwargs: Any) -> None:
            pass

    class _FakeState:
        def __init__(self) -> None:
            self.regs = _FakeRegs()
            self.memory = _FakeMemory()
            self.solver = types.SimpleNamespace(add=lambda *a, **k: None)

    fake = types.ModuleType("angr")

    class _FakeProject:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.factory = types.SimpleNamespace(
                blank_state=lambda *a, **k: _FakeState(), simgr=_unavailable
            )

        def hook(self, *args: Any, **kwargs: Any) -> None:
            pass

    real_simulation = prove_mod._run_simulation

    class _FakeSimProcedure:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    fake.Project = _FakeProject  # type: ignore[attr-defined]
    fake.SimProcedure = _FakeSimProcedure  # type: ignore[attr-defined]
    sim_stubs = {"ReturnUnconstrained": _FakeSimProcedure, "PathTerminator": _FakeSimProcedure}
    fake.SIM_PROCEDURES = {"stubs": sim_stubs}  # type: ignore[attr-defined]
    fake.exploration_techniques = types.SimpleNamespace(  # type: ignore[attr-defined]
        LoopSeer=lambda *a, **k: object()
    )
    fake.options = types.SimpleNamespace(  # type: ignore[attr-defined]
        ZERO_FILL_UNCONSTRAINED_MEMORY=1, ZERO_FILL_UNCONSTRAINED_REGISTERS=2
    )
    fake.factory = _unavailable  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "angr", fake)
    monkeypatch.setattr(prove_mod, "_run_simulation", real_simulation)
    simprocs_mod._WIN32_SIMPROCS = None
    monkeypatch.setattr(prove_mod, "_get_win32_simprocs", lambda: {})
    return fake


def _fake_run_simulation(
    monkeypatch: pytest.MonkeyPatch, first: tuple[list[Any], bool], second: tuple[list[Any], bool]
) -> None:
    """Patch ``_run_simulation`` to return crafted (states, timed_out) pairs."""
    calls = {"n": 0}

    def _fake(proj: object, state: object, **kw: object) -> tuple[list[Any], bool]:
        calls["n"] += 1
        return first if calls["n"] == 1 else second

    monkeypatch.setattr(prove_mod, "_run_simulation", _fake)


# ---------------------------------------------------------------------------
# 1. Timeout fail-closed
# ---------------------------------------------------------------------------


class TestTimeoutFailClosed:
    """A timed-out side must yield INCONCLUSIVE (never PROVEN), even when the
    partial terminal states happen to compare equal."""

    def _equal_states(self) -> tuple[Any, Any]:
        import claripy

        def _state(val: int) -> Any:
            st = types.SimpleNamespace()
            st.regs = types.SimpleNamespace()
            st.regs.eax = claripy.BVV(val, 32)
            st.regs.edx = claripy.BVV(0, 32)
            st.solver = types.SimpleNamespace()
            st.solver.constraints = []
            return st

        return _state(7), _state(7)

    def _prove_no_relocs(self, monkeypatch: pytest.MonkeyPatch) -> tuple[bool, str]:
        _install_fake_angr(monkeypatch)
        return prove_mod.prove_equivalence(b"\xc3", b"\xc3", None, "int __cdecl foo(void)")

    def test_timeout_orig_side_is_inconclusive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        o, c = self._equal_states()
        _fake_run_simulation(monkeypatch, ([o], True), ([c], False))
        proven, msg = self._prove_no_relocs(monkeypatch)
        assert proven is False
        assert "INCONCLUSIVE" in msg
        assert "timed out" in msg

    def test_timeout_comp_side_is_inconclusive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        o, c = self._equal_states()
        _fake_run_simulation(monkeypatch, ([o], False), ([c], True))
        proven, msg = self._prove_no_relocs(monkeypatch)
        assert proven is False
        assert "INCONCLUSIVE" in msg

    def test_no_timeout_still_proves_equal_states(self, monkeypatch: pytest.MonkeyPatch) -> None:
        o, c = self._equal_states()
        _fake_run_simulation(monkeypatch, ([o], False), ([c], False))
        proven, msg = self._prove_no_relocs(monkeypatch)
        assert proven is True, msg


# ---------------------------------------------------------------------------
# 2. Bounded symbolic copy length
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not has_claripy, reason="claripy not installed")
class TestCopyLengthBound:
    """``_copy_length_or_none`` refuses unbounded symbolic lengths (None)
    and honours concrete / solver-bounded lengths up to the cap."""

    def test_concrete_length_honoured(self) -> None:
        import claripy

        solver = claripy.Solver()
        assert simprocs_mod._copy_length_or_none(solver, claripy.BVV(17, 32)) == 17

    def test_concrete_length_above_cap_refused(self) -> None:
        """A concrete copy longer than the cap cannot be modelled in full:
        copying the prefix and leaving the tail unconstrained on both sides
        would prove only the compared prefix (P0), so it is refused like an
        unbounded symbolic length."""
        import claripy

        solver = claripy.Solver()
        assert simprocs_mod._copy_length_or_none(solver, claripy.BVV(5000, 32)) is None
        # At the cap exactly, the whole copy fits the model.
        assert (
            simprocs_mod._copy_length_or_none(solver, claripy.BVV(simprocs_mod._MEMCPY_MAX_LEN, 32))
            == simprocs_mod._MEMCPY_MAX_LEN
        )

    def test_unbounded_symbolic_length_refused(self) -> None:
        import claripy

        solver = claripy.Solver()
        n = claripy.BVS("n", 32)
        assert simprocs_mod._copy_length_or_none(solver, n) is None

    def test_bounded_symbolic_length_honoured_at_max(self) -> None:
        import claripy

        solver = claripy.Solver()
        n = claripy.BVS("n", 32)
        solver.add(claripy.ULE(n, 64))
        assert simprocs_mod._copy_length_or_none(solver, n) == 64

    def test_zero_length_copies_nothing(self) -> None:
        import claripy

        solver = claripy.Solver()
        assert simprocs_mod._copy_length_or_none(solver, claripy.BVV(0, 32)) == 0

    def test_unbounded_copy_raises(self) -> None:
        import claripy

        solver = claripy.Solver()
        with pytest.raises(RuntimeError, match="exceeds the .* copy cap"):
            simprocs_mod._raise_unbounded_copy(solver, claripy.BVS("n", 32))


# ---------------------------------------------------------------------------
# 3. Offset-map mismatch is INCONCLUSIVE
# ---------------------------------------------------------------------------


class TestOffsetMismatchInconclusive:
    """Call-site count mismatch must refuse the proof instead of patching
    the original blob at compiled offsets."""

    def test_mismatch_returns_inconclusive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Call-site counting is pure capstone logic: the assertion pins the
        # real counting decision, and the prove call pins the refusal that
        # follows it (no original-blob patching at compiled offsets).
        orig = bytes.fromhex("E8 FB FF FF 00 C3")
        comp = bytes.fromhex("90 C3")
        assert prove_mod._find_call_sites(orig) == [0]
        assert prove_mod._find_call_sites(comp) == []
        _install_fake_angr(monkeypatch)
        proven, msg = prove_mod.prove_equivalence(orig, comp, {1: "_ext"}, "int __cdecl foo(void)")
        assert proven is False
        assert "INCONCLUSIVE" in msg
        assert "call-site" in msg

    def test_mismatch_never_proves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _install_fake_angr(monkeypatch)
        # Two external calls in the original, one reloc'd call compiled.
        orig = bytes.fromhex("E8 FB FF FF FF E8 F6 FF FF FF C3")
        comp = bytes.fromhex("E8 00 00 00 00 C3")
        proven, msg = prove_mod.prove_equivalence(orig, comp, {1: "_ext"}, "int __cdecl foo(void)")
        assert proven is False
        assert "INCONCLUSIVE" in msg


# ---------------------------------------------------------------------------
# 4. Per-call-site stub return fingerprinting
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not has_claripy, reason="claripy not installed")
class TestStubArgFingerprint:
    """``_fingerprint_args`` equates identical formulas across projects but
    distinguishes distinct call sites / argument formulas."""

    def test_same_formula_same_fingerprint(self) -> None:
        import claripy

        s1, s2 = claripy.Solver(), claripy.Solver()
        a = claripy.BVS("arg", 32)
        b = claripy.BVS("arg", 32)
        assert prove_mod._fingerprint_args(s1, (a,)) == prove_mod._fingerprint_args(s2, (b,))

    def test_distinct_formulas_differ(self) -> None:
        import claripy

        solver = claripy.Solver()
        a = claripy.BVS("x", 32)
        b = claripy.BVS("y", 32)
        assert prove_mod._fingerprint_args(solver, (a,)) != prove_mod._fingerprint_args(
            solver, (b,)
        )

    def test_concrete_args_hash_by_value(self) -> None:
        import claripy

        solver = claripy.Solver()
        v1 = prove_mod._fingerprint_args(solver, (claripy.BVV(5, 32),))
        v2 = prove_mod._fingerprint_args(solver, (claripy.BVV(5, 32),))
        v3 = prove_mod._fingerprint_args(solver, (claripy.BVV(6, 32),))
        assert v1 == v2
        assert v1 != v3

    def test_empty_args_stable(self) -> None:
        import claripy

        solver = claripy.Solver()
        assert prove_mod._fingerprint_args(solver, ()) == prove_mod._fingerprint_args(solver, ())
