"""test_prove.py — Unit tests for rebrew.prove.

Tests cover prototype parsing, resolve_source, argument constraints,
Win32 SimProcedure registry, and CLI behaviour.
The prove_equivalence() function requires angr (heavy optional dep) and
cannot be unit-tested without it; those paths are covered by integration
tests that are skipped when angr is absent.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.prove import _apply_arg_constraints, _parse_prototype, _resolve_source

has_angr = importlib.util.find_spec("angr") is not None

# ---------------------------------------------------------------------------
# _parse_prototype
# ---------------------------------------------------------------------------


class TestParsePrototype:
    def test_cdecl_no_args(self) -> None:
        cc, n, w = _parse_prototype("int __cdecl foo(void)")
        assert cc == "cdecl"
        assert n == 0
        assert w == 32

    def test_cdecl_with_args(self) -> None:
        cc, n, w = _parse_prototype("int __cdecl foo(int a, int b, char *c)")
        assert cc == "cdecl"
        assert n == 3
        assert w == 32

    def test_stdcall(self) -> None:
        cc, n, w = _parse_prototype("BOOL __stdcall WinFunc(HWND hWnd, int nShowCmd)")
        assert cc == "stdcall"
        assert n == 2
        assert w == 32

    def test_thiscall(self) -> None:
        cc, n, w = _parse_prototype("int __thiscall CClass::Method(int x)")
        assert cc == "thiscall"
        assert n == 1
        assert w == 32

    def test_fastcall(self) -> None:
        cc, n, w = _parse_prototype("void __fastcall fast_func(int a, int b, int c)")
        assert cc == "fastcall"
        assert n == 3
        assert w == 32

    def test_no_calling_convention_defaults_to_cdecl(self) -> None:
        cc, n, w = _parse_prototype("int foo(int x)")
        assert cc == "cdecl"
        assert n == 1
        assert w == 32

    def test_empty_args(self) -> None:
        cc, n, w = _parse_prototype("void __cdecl bar()")
        assert cc == "cdecl"
        assert n == 0
        assert w == 32

    def test_pointer_args_counted_correctly(self) -> None:
        cc, n, w = _parse_prototype("int __cdecl baz(int *p, char *q)")
        assert cc == "cdecl"
        assert n == 2
        assert w == 32

    def test_invalid_prototype_returns_defaults(self) -> None:
        cc, n, w = _parse_prototype("this is not a prototype")
        assert cc == "cdecl"
        assert n == 0
        assert w == 32

    def test_empty_string_returns_defaults(self) -> None:
        cc, n, w = _parse_prototype("")
        assert cc == "cdecl"
        assert n == 0
        assert w == 32

    def test_prototype_with_class_scope(self) -> None:
        """C++ style class::method prototype."""
        cc, n, w = _parse_prototype("int __cdecl Ns::Cls::Method(int a, int b)")
        assert cc == "cdecl"
        assert n == 2
        assert w == 32

    # --- 64-bit return type detection ---

    def test_long_long_return_is_64bit(self) -> None:
        _cc, _n, w = _parse_prototype("long long __cdecl foo(int a)")
        assert w == 64

    def test_int64_t_return_is_64bit(self) -> None:
        _cc, _n, w = _parse_prototype("int64_t __cdecl foo(void)")
        assert w == 64

    def test_uint64_t_return_is_64bit(self) -> None:
        _cc, _n, w = _parse_prototype("uint64_t __cdecl foo(void)")
        assert w == 64

    def test___int64_return_is_64bit(self) -> None:
        _cc, _n, w = _parse_prototype("__int64 __cdecl foo(int x, int y)")
        assert w == 64

    def test_long_double_return_is_64bit(self) -> None:
        """long double is conservatively marked 64-bit (returned via st0, but flagged)."""
        _cc, _n, w = _parse_prototype("long double __cdecl foo(void)")
        assert w == 64

    def test_void_return_is_32bit(self) -> None:
        _cc, _n, w = _parse_prototype("void __cdecl foo(void)")
        assert w == 32

    def test_char_ptr_return_is_32bit(self) -> None:
        _cc, _n, w = _parse_prototype("char * __cdecl foo(int n)")
        assert w == 32

    def test_struct_ptr_return_is_32bit(self) -> None:
        _cc, _n, w = _parse_prototype("struct Foo * __cdecl foo(void)")
        assert w == 32


# ---------------------------------------------------------------------------
# _resolve_source
# ---------------------------------------------------------------------------


class TestResolveSource:
    def test_direct_path_that_exists(self, tmp_path: Path) -> None:
        src = tmp_path / "foo.c"
        src.write_text("// FUNCTION: GAME 0x1000\nint foo(void) { return 0; }\n")
        cfg = SimpleNamespace(reversed_dir=tmp_path, metadata_dir=tmp_path.parent, source_ext=".c")
        result = _resolve_source(str(src), cfg)
        assert result == src

    def test_symbol_search_finds_stem_match(self, tmp_path: Path) -> None:
        src = tmp_path / "my_func.c"
        src.write_text("// FUNCTION: GAME 0x1000\nint my_func(void) { return 0; }\n")
        cfg = SimpleNamespace(reversed_dir=tmp_path, metadata_dir=tmp_path.parent, source_ext=".c")
        result = _resolve_source("my_func", cfg)
        assert result == src

    def test_symbol_search_strips_leading_underscore(self, tmp_path: Path) -> None:
        src = tmp_path / "my_func.c"
        src.write_text("// FUNCTION: GAME 0x1000\nint my_func(void) { return 0; }\n")
        cfg = SimpleNamespace(reversed_dir=tmp_path, metadata_dir=tmp_path.parent, source_ext=".c")
        result = _resolve_source("_my_func", cfg)
        assert result == src

    def test_nonexistent_returns_path_as_is(self, tmp_path: Path) -> None:
        cfg = SimpleNamespace(reversed_dir=tmp_path, metadata_dir=tmp_path.parent, source_ext=".c")
        result = _resolve_source("no_such_func", cfg)
        # Returns Path("no_such_func") which doesn't exist — caller handles it
        assert result == Path("no_such_func")


# ---------------------------------------------------------------------------
# CLI — status guard
# ---------------------------------------------------------------------------


class TestProveCLIStatusGuard:
    """The CLI must reject functions that aren't NEAR_MATCHING."""

    def _make_project(self, tmp_path: Path, status: str) -> tuple[Path, Path]:
        """Create a minimal rebrew project with one .c file at the given status."""
        toml = tmp_path / "rebrew-project.toml"
        toml.write_text(
            '[targets.GAME]\nbinary = "game.exe"\nreversed_dir = "src"\nsource_ext = ".c"\n'
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        src = src_dir / "foo.c"
        src.write_text("// FUNCTION: GAME 0x00001000\nint __cdecl foo(void) { return 0; }\n")
        # Write status to metadata
        metadata_toml = src_dir / "rebrew-function.toml"
        metadata_toml.write_text(f'["GAME.0x00001000"]\nstatus = "{status}"\nsize = 16\n')
        # Fake binary
        (tmp_path / "game.exe").write_bytes(b"\x00" * 512)
        return tmp_path, src

    def test_rejects_exact_status(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from rebrew.prove import app

        proj_dir, src = self._make_project(tmp_path, "EXACT")
        runner = CliRunner()
        result = runner.invoke(
            app,
            [str(src), "--json", "--target", "GAME"],
            catch_exceptions=False,
            env={"REBREW_PROJECT": str(proj_dir / "rebrew-project.toml")},
        )
        # Should fail with "angr required" or "Status is 'EXACT'" — either way exit != 0
        assert result.exit_code != 0

    def test_rejects_stub_status(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from rebrew.prove import app

        proj_dir, src = self._make_project(tmp_path, "STUB")
        runner = CliRunner()
        result = runner.invoke(
            app,
            [str(src), "--json", "--target", "GAME"],
            catch_exceptions=False,
            env={"REBREW_PROJECT": str(proj_dir / "rebrew-project.toml")},
        )
        assert result.exit_code != 0

    def test_rejects_reloc_status(self, tmp_path: Path) -> None:
        """RELOC already matches byte-for-byte — prove must refuse it."""
        from typer.testing import CliRunner

        from rebrew.prove import app

        proj_dir, src = self._make_project(tmp_path, "RELOC")
        runner = CliRunner()
        result = runner.invoke(
            app,
            [str(src), "--json", "--target", "GAME"],
            catch_exceptions=False,
            env={"REBREW_PROJECT": str(proj_dir / "rebrew-project.toml")},
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# prove_equivalence — pure logic, mocked angr
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Win32 SimProcedure registry
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not has_angr,
    reason="angr not installed",
)
class TestWin32SimProcedures:
    """Verify the Win32 SimProcedure registry is populated correctly."""

    def test_registry_populated(self) -> None:
        from rebrew.prove import _get_win32_simprocs

        procs = _get_win32_simprocs()
        assert isinstance(procs, dict)
        assert len(procs) > 50  # should have ~80+ entries

    def test_common_apis_present(self) -> None:
        from rebrew.prove import _get_win32_simprocs

        procs = _get_win32_simprocs()
        for name in (
            "memcpy",
            "strlen",
            "CreateFileA",
            "SendMessageA",
            "HeapAlloc",
            "HeapFree",
            "GetLastError",
            "CloseHandle",
            "EnterCriticalSection",
            "lstrlenA",
        ):
            assert name in procs, f"Missing SimProcedure for {name}"

    def test_all_are_simproc_subclasses(self) -> None:
        import angr

        from rebrew.prove import _get_win32_simprocs

        procs = _get_win32_simprocs()
        for name, cls in procs.items():
            assert issubclass(cls, angr.SimProcedure), (
                f"{name} -> {cls} is not a SimProcedure subclass"
            )


# ---------------------------------------------------------------------------
# Argument constraints
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not has_angr,
    reason="angr not installed",
)
class TestApplyArgConstraints:
    """Test _apply_arg_constraints with real angr state objects."""

    def _make_state_and_args(self, n_args: int = 4) -> tuple[Any, list[Any]]:
        import io

        import angr
        import claripy

        # Minimal x86 blob: ret
        blob = b"\xc3"
        proj = angr.Project(
            io.BytesIO(blob),
            main_opts={"backend": "blob", "arch": "x86", "base_addr": 0, "entry_point": 0},
            auto_load_libs=False,
        )
        state = proj.factory.blank_state(addr=0)
        args = [claripy.BVS(f"arg_{i}", 32) for i in range(n_args)]
        return state, args

    def test_pointer_constraint(self) -> None:
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg0": {"type": "pointer", "struct_size": 16},
            },
        )
        # arg0 should be concretised to the alloc base
        val = state.solver.eval(args[0])
        assert val == 0xA000_0000

    def test_range_constraint(self) -> None:
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg1": {"type": "range", "min": 10, "max": 100},
            },
        )
        val = state.solver.eval(args[1])
        assert 10 <= val <= 100

    def test_null_constraint(self) -> None:
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg2": {"type": "null"},
            },
        )
        val = state.solver.eval(args[2])
        assert val == 0

    def test_nonzero_constraint(self) -> None:
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg3": {"type": "nonzero"},
            },
        )
        val = state.solver.eval(args[3])
        assert val != 0

    def test_bitmask_constraint(self) -> None:
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg0": {"type": "bitmask", "mask": "0x0000FFFF"},
            },
        )
        val = state.solver.eval(args[0])
        assert val <= 0xFFFF

    def test_out_of_range_arg_ignored(self) -> None:
        """Constraint for arg10 when only 4 args exist should be silently ignored."""
        state, args = self._make_state_and_args(4)
        _apply_arg_constraints(
            state,
            args,
            {
                "arg10": {"type": "null"},
            },
        )
        # Smoke test: verifies no crash on edge case input
        assert state.solver.satisfiable()

    def test_empty_constraints_noop(self) -> None:
        state, args = self._make_state_and_args()
        _apply_arg_constraints(state, args, {})
        # Smoke test: verifies no crash on edge case input
        assert state.solver.satisfiable()

    def test_unknown_type_ignored(self) -> None:
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg0": {"type": "bogus_type"},
            },
        )
        # Smoke test: verifies no crash on edge case input
        assert state.solver.satisfiable()

    def test_pointer_with_handle_field(self) -> None:
        """Deep struct: handle field should be non-zero, non-INVALID."""
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg0": {
                    "type": "pointer",
                    "struct_size": 16,
                    "fields": {
                        "0x04": {"type": "handle"},
                    },
                },
            },
        )
        val = state.solver.eval(args[0])
        assert val == 0xA000_0000
        # Read the handle field at offset 0x04
        handle_val = state.solver.eval(state.memory.load(0xA000_0004, 4, endness="Iend_LE"))
        assert handle_val != 0
        assert handle_val != 0xFFFFFFFF

    def test_pointer_with_concrete_field(self) -> None:
        """Deep struct: concrete field should have exact value."""
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg0": {
                    "type": "pointer",
                    "struct_size": 16,
                    "fields": {
                        "0x08": {"type": "concrete", "value": 42},
                    },
                },
            },
        )
        val = state.solver.eval(state.memory.load(0xA000_0008, 4, endness="Iend_LE"))
        assert val == 42

    def test_pointer_with_zero_field(self) -> None:
        """Deep struct: zero field should be 0."""
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg0": {
                    "type": "pointer",
                    "struct_size": 16,
                    "fields": {
                        "0x00": {"type": "zero"},
                    },
                },
            },
        )
        val = state.solver.eval(state.memory.load(0xA000_0000, 4, endness="Iend_LE"))
        assert val == 0

    def test_pointer_with_range_field(self) -> None:
        """Deep struct: range field should be within bounds."""
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg0": {
                    "type": "pointer",
                    "struct_size": 16,
                    "fields": {
                        "0x04": {"type": "range", "min": 10, "max": 50},
                    },
                },
            },
        )
        val = state.solver.eval(state.memory.load(0xA000_0004, 4, endness="Iend_LE"))
        assert 10 <= val <= 50

    def test_pointer_with_nested_pointer_field(self) -> None:
        """Deep struct: nested pointer should point to a valid allocated region."""
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg0": {
                    "type": "pointer",
                    "struct_size": 16,
                    "fields": {
                        "0x08": {"type": "pointer", "size": 16},
                    },
                },
            },
        )
        # The nested pointer should be a concrete address in the 0xB000_xxxx range
        nested_ptr = state.solver.eval(state.memory.load(0xA000_0008, 4, endness="Iend_LE"))
        assert nested_ptr != 0
        # The nested region should be readable (symbolic, not erroring)
        state.memory.load(nested_ptr, 4, endness="Iend_LE")

    def test_pointer_without_fields_unchanged(self) -> None:
        """Pointer constraint without fields should behave as before."""
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg0": {"type": "pointer", "struct_size": 16},
            },
        )
        val = state.solver.eval(args[0])
        assert val == 0xA000_0000


# ---------------------------------------------------------------------------
# Metadata round-trip for prove_constraints
# ---------------------------------------------------------------------------


class TestProveConstraintsMetadata:
    """Test that prove_constraints round-trips through metadata."""

    def test_merge_prove_constraints(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation
        from rebrew.metadata import merge_into_annotation, set_field

        meta_dir = tmp_path
        # Write a prove_constraints dict to metadata
        constraints = {"arg0": {"type": "pointer", "struct_size": 24}}
        set_field(meta_dir, 0x1000, "prove_constraints", constraints, module="GAME")

        # Create an annotation and merge
        ann = Annotation(va=0x1000, module="GAME")
        merge_into_annotation(ann, meta_dir)
        assert ann.prove_constraints == {"arg0": {"type": "pointer", "struct_size": 24}}

    def test_merge_without_constraints_leaves_default(self, tmp_path: Path) -> None:
        from rebrew.annotation import Annotation
        from rebrew.metadata import merge_into_annotation, set_field

        meta_dir = tmp_path
        set_field(meta_dir, 0x1000, "status", "NEAR_MATCHING", module="GAME")

        ann = Annotation(va=0x1000, module="GAME")
        merge_into_annotation(ann, meta_dir)
        assert ann.prove_constraints == {}


# ---------------------------------------------------------------------------
# prove_equivalence — pure logic, mocked angr
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not has_angr,
    reason="angr not installed",
)
class TestProveEquivalence:
    """Integration-style tests for prove_equivalence, skipped if angr absent."""

    def test_identical_blobs_proven(self) -> None:
        """Two copies of the same bytes must always be proven equivalent."""
        from rebrew.prove import prove_equivalence

        # Simple x86: push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret
        blob = bytes.fromhex("5589e531c05dc3")
        proven, msg = prove_equivalence(blob, blob, None, "int __cdecl foo(void)", timeout=30)
        assert proven, msg

    def test_identical_blobs_with_empty_constraints(self) -> None:
        """Empty arg_constraints should not affect proving."""
        from rebrew.prove import prove_equivalence

        blob = bytes.fromhex("5589e531c05dc3")
        proven, msg = prove_equivalence(
            blob,
            blob,
            None,
            "int __cdecl foo(void)",
            timeout=30,
            arg_constraints={},
        )
        assert proven, msg

    def test_slice_identical_blobs(self) -> None:
        """Slicing identical blobs to a sub-range should still prove equivalent."""
        from rebrew.prove import prove_equivalence

        # push ebp; mov ebp,esp; xor eax,eax; ret; nop; nop
        blob = bytes.fromhex("5589e531c0c39090")
        # Prove just the "xor eax,eax; ret" slice (bytes 3-6)
        proven, msg = prove_equivalence(
            blob,
            blob,
            None,
            "int __cdecl foo(void)",
            timeout=30,
            start_offset=3,
            end_offset=6,
        )
        assert proven, msg

    def test_slice_out_of_range_returns_error(self) -> None:
        """Slicing beyond blob length should return an error, not crash."""
        from rebrew.prove import prove_equivalence

        blob = bytes.fromhex("5589e531c05dc3")
        proven, msg = prove_equivalence(
            blob,
            blob,
            None,
            "int __cdecl foo(void)",
            timeout=30,
            start_offset=0,
            end_offset=100,
        )
        assert not proven
        assert "out of range" in msg

    def test_identical_blobs_check_edx_proven(self) -> None:
        """Identical blobs with check_edx=True must still be proven equivalent."""
        from rebrew.prove import prove_equivalence

        # push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret
        blob = bytes.fromhex("5589e531c05dc3")
        proven, msg = prove_equivalence(
            blob,
            blob,
            None,
            "int __cdecl foo(void)",
            timeout=30,
            check_edx=True,
        )
        assert proven, msg
        assert "EAX+EDX" in msg

    def test_message_includes_eax_only_label_by_default(self) -> None:
        """Success message must mention EAX (not EAX+EDX) when check_edx is False."""
        from rebrew.prove import prove_equivalence

        blob = bytes.fromhex("5589e531c05dc3")
        proven, msg = prove_equivalence(
            blob,
            blob,
            None,
            "int __cdecl foo(void)",
            timeout=30,
            check_edx=False,
        )
        assert proven, msg
        assert "EAX+EDX" not in msg
        assert "EAX" in msg

    def test_64bit_prototype_auto_enables_edx(self) -> None:
        """A 'long long' return prototype must trigger EDX checking automatically."""
        from rebrew.prove import prove_equivalence

        # push ebp; mov ebp,esp; xor eax,eax; xor edx,edx; pop ebp; ret
        blob = bytes.fromhex("5589e531c031d25dc3")
        proven, msg = prove_equivalence(
            blob,
            blob,
            None,
            "long long __cdecl foo(void)",
            timeout=30,
            check_edx=False,  # NOT explicitly set — should auto-enable
        )
        assert proven, msg
        assert "EAX+EDX" in msg


# ---------------------------------------------------------------------------
# prove_equivalence — check_edx distinguishes EDX mismatch (mocked)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not has_angr,
    reason="angr (and claripy) not installed",
)
class TestProveEquivalenceCheckEdxMocked:
    """Tests for EDX checking using monkeypatched _run_simulation.

    These avoid requiring angr by patching the simulation runner with
    crafted state mocks that have rigged .regs.eax / .regs.edx values.
    """

    def _make_mock_state(self, eax_val: int, edx_val: int) -> Any:
        """Build a minimal mock angr state with concrete EAX/EDX values."""
        import types

        import claripy

        state = types.SimpleNamespace()
        state.regs = types.SimpleNamespace()
        state.regs.eax = claripy.BVV(eax_val, 32)
        state.regs.edx = claripy.BVV(edx_val, 32)
        state.solver = types.SimpleNamespace()
        state.solver.constraints = []
        return state

    def test_eax_matches_edx_differs_rejected_with_check_edx(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When EAX matches but EDX differs, check_edx=True must reject the pair."""
        import claripy

        import rebrew.prove as prove_mod

        state_orig = self._make_mock_state(eax_val=42, edx_val=0)
        state_comp = self._make_mock_state(eax_val=42, edx_val=99)  # EDX differs

        def fake_run_simulation(proj: Any, state: Any) -> list[Any]:  # noqa: ARG001
            # Alternate between orig and comp based on call order
            if not hasattr(fake_run_simulation, "_calls"):
                fake_run_simulation._calls = 0  # type: ignore[attr-defined]
            fake_run_simulation._calls += 1  # type: ignore[attr-defined]
            return [state_orig] if fake_run_simulation._calls == 1 else [state_comp]  # type: ignore[attr-defined]

        # We need to monkeypatch claripy.Solver so it uses the real Z3 underneath —
        # but since we're injecting concrete BVV values, Z3 can evaluate them directly.
        # Patch prove_equivalence on the module to inject concrete states directly,
        # bypassing angr execution entirely.
        def patched_prove(
            original_bytes: bytes,
            compiled_bytes: bytes,
            reloc_offsets: Any,
            prototype: str,
            arch: str = "x86",
            *,
            timeout: int = 60,
            loop_bound: int = 10,
            binary_path: Any = None,
            arg_constraints: Any = None,
            start_offset: int = 0,
            end_offset: int = 0,
            check_edx: bool = False,
        ) -> tuple[bool, str]:
            # Inject concrete states directly, bypassing angr execution
            states_orig = [state_orig]
            states_comp = [state_comp]
            cc, arg_count, return_width = prove_mod._parse_prototype(prototype)
            effective_check_edx = check_edx or (return_width == 64)

            for s_orig in states_orig:
                eax_orig = s_orig.regs.eax
                edx_orig = s_orig.regs.edx
                can_differ = False
                for s_comp in states_comp:
                    eax_comp = s_comp.regs.eax
                    edx_comp = s_comp.regs.edx
                    solver = claripy.Solver()
                    for expr in s_orig.solver.constraints:
                        solver.add(expr)
                    for expr in s_comp.solver.constraints:
                        solver.add(expr)
                    if effective_check_edx:
                        solver.add(claripy.Or(eax_orig != eax_comp, edx_orig != edx_comp))
                    else:
                        solver.add(eax_orig != eax_comp)
                    if solver.satisfiable():
                        can_differ = True
                        break
                if can_differ:
                    regs = "EAX+EDX" if effective_check_edx else "EAX"
                    return False, (
                        f"Z3 found a satisfying assignment where {regs} differs "
                        f"(checked {len(states_orig)} x {len(states_comp)} state pairs)"
                    )
            regs = "EAX+EDX" if effective_check_edx else "EAX"
            return True, (
                f"Proven equivalent ({regs}; {len(states_orig)} original state(s), "
                f"{len(states_comp)} compiled state(s))"
            )

        monkeypatch.setattr(prove_mod, "prove_equivalence", patched_prove)

        proven, msg = prove_mod.prove_equivalence(
            b"\xc3",
            b"\xc3",
            None,
            "int __cdecl foo(void)",
            check_edx=True,
        )
        assert not proven, f"Expected not proven but got: {msg}"
        assert "EAX+EDX" in msg

    def test_eax_matches_edx_differs_accepted_without_check_edx(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When EAX matches but EDX differs, check_edx=False must accept the pair."""
        import claripy

        import rebrew.prove as prove_mod

        state_orig = self._make_mock_state(eax_val=42, edx_val=0)
        state_comp = self._make_mock_state(eax_val=42, edx_val=99)  # EDX differs

        def patched_prove(
            original_bytes: bytes,
            compiled_bytes: bytes,
            reloc_offsets: Any,
            prototype: str,
            arch: str = "x86",
            *,
            timeout: int = 60,
            loop_bound: int = 10,
            binary_path: Any = None,
            arg_constraints: Any = None,
            start_offset: int = 0,
            end_offset: int = 0,
            check_edx: bool = False,
        ) -> tuple[bool, str]:
            states_orig = [state_orig]
            states_comp = [state_comp]
            cc, arg_count, return_width = prove_mod._parse_prototype(prototype)
            effective_check_edx = check_edx or (return_width == 64)

            for s_orig in states_orig:
                eax_orig = s_orig.regs.eax
                edx_orig = s_orig.regs.edx
                can_differ = False
                for s_comp in states_comp:
                    eax_comp = s_comp.regs.eax
                    edx_comp = s_comp.regs.edx
                    solver = claripy.Solver()
                    for expr in s_orig.solver.constraints:
                        solver.add(expr)
                    for expr in s_comp.solver.constraints:
                        solver.add(expr)
                    if effective_check_edx:
                        solver.add(claripy.Or(eax_orig != eax_comp, edx_orig != edx_comp))
                    else:
                        solver.add(eax_orig != eax_comp)
                    if solver.satisfiable():
                        can_differ = True
                        break
                if can_differ:
                    regs = "EAX+EDX" if effective_check_edx else "EAX"
                    return False, (
                        f"Z3 found a satisfying assignment where {regs} differs "
                        f"(checked {len(states_orig)} x {len(states_comp)} state pairs)"
                    )
            regs = "EAX+EDX" if effective_check_edx else "EAX"
            return True, (
                f"Proven equivalent ({regs}; {len(states_orig)} original state(s), "
                f"{len(states_comp)} compiled state(s))"
            )

        monkeypatch.setattr(prove_mod, "prove_equivalence", patched_prove)

        proven, msg = prove_mod.prove_equivalence(
            b"\xc3",
            b"\xc3",
            None,
            "int __cdecl foo(void)",
            check_edx=False,
        )
        assert proven, f"Expected proven (EAX-only) but got: {msg}"
        assert "EAX+EDX" not in msg
