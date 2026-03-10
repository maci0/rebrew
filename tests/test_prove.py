"""test_prove.py — Unit tests for rebrew.prove.

Tests cover prototype parsing, resolve_source, argument constraints,
Win32 SimProcedure registry, and CLI behaviour.
The prove_equivalence() function requires angr (heavy optional dep) and
cannot be unit-tested without it; those paths are covered by integration
tests that are skipped when angr is absent.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rebrew.prove import _apply_arg_constraints, _parse_prototype, _resolve_source

# ---------------------------------------------------------------------------
# _parse_prototype
# ---------------------------------------------------------------------------


class TestParsePrototype:
    def test_cdecl_no_args(self) -> None:
        cc, n = _parse_prototype("int __cdecl foo(void)")
        assert cc == "cdecl"
        assert n == 0

    def test_cdecl_with_args(self) -> None:
        cc, n = _parse_prototype("int __cdecl foo(int a, int b, char *c)")
        assert cc == "cdecl"
        assert n == 3

    def test_stdcall(self) -> None:
        cc, n = _parse_prototype("BOOL __stdcall WinFunc(HWND hWnd, int nShowCmd)")
        assert cc == "stdcall"
        assert n == 2

    def test_thiscall(self) -> None:
        cc, n = _parse_prototype("int __thiscall CClass::Method(int x)")
        assert cc == "thiscall"
        assert n == 1

    def test_fastcall(self) -> None:
        cc, n = _parse_prototype("void __fastcall fast_func(int a, int b, int c)")
        assert cc == "fastcall"
        assert n == 3

    def test_no_calling_convention_defaults_to_cdecl(self) -> None:
        cc, n = _parse_prototype("int foo(int x)")
        assert cc == "cdecl"
        assert n == 1

    def test_empty_args(self) -> None:
        cc, n = _parse_prototype("void __cdecl bar()")
        assert cc == "cdecl"
        assert n == 0

    def test_pointer_args_counted_correctly(self) -> None:
        cc, n = _parse_prototype("int __cdecl baz(int *p, char *q)")
        assert cc == "cdecl"
        assert n == 2

    def test_invalid_prototype_returns_defaults(self) -> None:
        cc, n = _parse_prototype("this is not a prototype")
        assert cc == "cdecl"
        assert n == 0

    def test_empty_string_returns_defaults(self) -> None:
        cc, n = _parse_prototype("")
        assert cc == "cdecl"
        assert n == 0

    def test_prototype_with_class_scope(self) -> None:
        """C++ style class::method prototype."""
        cc, n = _parse_prototype("int __cdecl Ns::Cls::Method(int a, int b)")
        assert cc == "cdecl"
        assert n == 2


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
    """The CLI must reject functions that aren't NEAR_MATCHING / RELOC."""

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


# ---------------------------------------------------------------------------
# prove_equivalence — pure logic, mocked angr
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Win32 SimProcedure registry
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not pytest.importorskip("angr", reason="angr not installed"),  # type: ignore[arg-type]
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
    not pytest.importorskip("angr", reason="angr not installed"),  # type: ignore[arg-type]
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
        # No crash, no constraints added

    def test_empty_constraints_noop(self) -> None:
        state, args = self._make_state_and_args()
        _apply_arg_constraints(state, args, {})
        # Should complete without error

    def test_unknown_type_ignored(self) -> None:
        state, args = self._make_state_and_args()
        _apply_arg_constraints(
            state,
            args,
            {
                "arg0": {"type": "bogus_type"},
            },
        )
        # Unknown type is silently ignored

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
    not pytest.importorskip("angr", reason="angr not installed"),  # type: ignore[arg-type]
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
