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

from rebrew.prove import _apply_arg_constraints, _parse_prototype, prove_equivalence

FIXTURES = Path(__file__).parent / "fixtures"

has_angr = importlib.util.find_spec("angr") is not None

# ---------------------------------------------------------------------------
# _parse_prototype
# ---------------------------------------------------------------------------


class TestParsePrototype:
    def test_cdecl_no_args(self) -> None:
        cc, n, w, is_void = _parse_prototype("int __cdecl foo(void)")
        assert cc == "cdecl"
        assert n == 0
        assert w == 32

    def test_cdecl_with_args(self) -> None:
        cc, n, w, is_void = _parse_prototype("int __cdecl foo(int a, int b, char *c)")
        assert cc == "cdecl"
        assert n == 3
        assert w == 32

    def test_stdcall(self) -> None:
        cc, n, w, is_void = _parse_prototype("BOOL __stdcall WinFunc(HWND hWnd, int nShowCmd)")
        assert cc == "stdcall"
        assert n == 2
        assert w == 32

    def test_thiscall(self) -> None:
        cc, n, w, is_void = _parse_prototype("int __thiscall CClass::Method(int x)")
        assert cc == "thiscall"
        assert n == 1
        assert w == 32

    def test_fastcall(self) -> None:
        cc, n, w, is_void = _parse_prototype("void __fastcall fast_func(int a, int b, int c)")
        assert cc == "fastcall"
        assert n == 3
        assert w == 32

    def test_no_calling_convention_defaults_to_cdecl(self) -> None:
        cc, n, w, is_void = _parse_prototype("int foo(int x)")
        assert cc == "cdecl"
        assert n == 1
        assert w == 32

    def test_empty_args(self) -> None:
        cc, n, w, is_void = _parse_prototype("void __cdecl bar()")
        assert cc == "cdecl"
        assert n == 0
        assert w == 32

    def test_pointer_args_counted_correctly(self) -> None:
        cc, n, w, is_void = _parse_prototype("int __cdecl baz(int *p, char *q)")
        assert cc == "cdecl"
        assert n == 2
        assert w == 32

    def test_invalid_prototype_returns_defaults(self) -> None:
        cc, n, w, is_void = _parse_prototype("this is not a prototype")
        assert cc == "cdecl"
        assert n == 0
        assert w == 32
        assert is_void is False

    def test_empty_string_returns_defaults(self) -> None:
        cc, n, w, is_void = _parse_prototype("")
        assert cc == "cdecl"
        assert n == 0
        assert w == 32
        assert is_void is False

    def test_prototype_with_class_scope(self) -> None:
        """C++ style class::method prototype."""
        cc, n, w, is_void = _parse_prototype("int __cdecl Ns::Cls::Method(int a, int b)")
        assert cc == "cdecl"
        assert n == 2
        assert w == 32

    # --- 64-bit return type detection ---

    def test_long_long_return_is_64bit(self) -> None:
        _cc, _n, w, is_void = _parse_prototype("long long __cdecl foo(int a)")
        assert w == 64

    def test_int64_t_return_is_64bit(self) -> None:
        _cc, _n, w, is_void = _parse_prototype("int64_t __cdecl foo(void)")
        assert w == 64

    def test_uint64_t_return_is_64bit(self) -> None:
        _cc, _n, w, is_void = _parse_prototype("uint64_t __cdecl foo(void)")
        assert w == 64

    def test___int64_return_is_64bit(self) -> None:
        _cc, _n, w, is_void = _parse_prototype("__int64 __cdecl foo(int x, int y)")
        assert w == 64

    def test_long_double_return_is_64bit(self) -> None:
        """long double is conservatively marked 64-bit (returned via st0, but flagged)."""
        _cc, _n, w, is_void = _parse_prototype("long double __cdecl foo(void)")
        assert w == 64

    def test_void_return_is_32bit(self) -> None:
        _cc, _n, w, is_void = _parse_prototype("void __cdecl foo(void)")
        assert w == 32
        assert is_void is True

    def test_char_ptr_return_is_32bit(self) -> None:
        _cc, _n, w, is_void = _parse_prototype("char * __cdecl foo(int n)")
        assert w == 32
        assert is_void is False

    def test_void_pointer_return_is_not_void(self) -> None:
        """``void*`` returns a pointer (EAX is meaningful) — not a void function."""
        _cc, _n, w, is_void = _parse_prototype("void * __cdecl foo(void)")
        assert w == 32
        assert is_void is False

    def test_struct_ptr_return_is_32bit(self) -> None:
        _cc, _n, w, is_void = _parse_prototype("struct Foo * __cdecl foo(void)")
        assert w == 32


class TestVoidFunctionGuard:
    """void functions leave EAX undefined — prove must not compare it.

    ``check_eax=False`` with no watched VAs would make the equivalence check
    trivially true (an empty disjunction is unsatisfiable), so it must be
    refused up front; with watched VAs it proceeds and compares memory only.
    """

    def test_void_without_watch_vas_refused(self) -> None:
        proven, msg = prove_equivalence(
            b"\xc3", b"\xc3", None, "void __cdecl foo(void)", check_eax=False
        )
        assert proven is False
        assert "no --watch-va" in msg

    def test_void_with_watch_vas_not_refused(self) -> None:
        # Guard passes; angr executes and reports what it compared (the exact
        # equivalence verdict depends on the blobs, but the refusal message
        # must be absent and the label must mention the watched memory).
        proven, msg = prove_equivalence(
            b"\xc3",
            b"\xc3",
            None,
            "void __cdecl foo(void)",
            check_eax=False,
            watched_vas=[0x1000],
        )
        assert "no --watch-va" not in msg
        assert not (proven is False and "nothing to compare" in msg)


# ---------------------------------------------------------------------------
# CLI — status guard
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not has_angr,
    reason="angr not installed (run 'uv sync --all-extras' to enable prove tests)",
)
class TestProveCLIStatusGuard:
    """The CLI must reject functions that aren't NEAR_MATCHING/SIZE_MISMATCH.

    Invocation pattern matters: options must precede the positional SOURCE
    (``--json --target GAME foo.c``), and the process must run inside the
    project dir (``monkeypatch.chdir``) — the old source-first form made
    typer reject the call as "No such command", silently passing every test.
    """

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
        # Write status to metadata — cfg.metadata_dir is reversed_dir.parent,
        # i.e. the project root for reversed_dir="src".
        metadata_toml = tmp_path / "rebrew-functions.toml"
        metadata_toml.write_text(f'["GAME.0x00001000"]\nstatus = "{status}"\nsize = 16\n')
        # Real PE fixture (parseable) — downstream needs a valid binary.
        import shutil

        shutil.copy(FIXTURES / "mini_pe.exe", tmp_path / "game.exe")
        return tmp_path, src

    def _invoke(self, proj_dir: Path, src: Path, monkeypatch: pytest.MonkeyPatch):
        from typer.testing import CliRunner

        from rebrew.prove import app

        monkeypatch.chdir(proj_dir)
        return CliRunner().invoke(
            app,
            ["--json", "--target", "GAME", str(src)],
            catch_exceptions=False,
        )

    def test_rejects_exact_status(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        proj_dir, src = self._make_project(tmp_path, "EXACT")
        result = self._invoke(proj_dir, src, monkeypatch)
        assert result.exit_code != 0
        assert "expected NEAR_MATCHING or SIZE_MISMATCH" in result.output

    def test_rejects_stub_status(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        proj_dir, src = self._make_project(tmp_path, "STUB")
        result = self._invoke(proj_dir, src, monkeypatch)
        assert result.exit_code != 0
        assert "expected NEAR_MATCHING or SIZE_MISMATCH" in result.output

    def test_stub_with_cached_near_matching_passes_gate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Effective-status overlay: a STUB whose verify-cache entry says
        NEAR_MATCHING (measured truth — the metadata STATUS lags) must pass
        prove's gate.  Regression: flag-swept functions stayed STUB in
        metadata while the cache said NEAR_MATCHING, so prove refused them."""
        import json

        proj_dir, src = self._make_project(tmp_path, "STUB")
        # Write a target-guarded verify cache claiming NEAR_MATCHING for the VA.
        va = 0x1000
        cache_dir = proj_dir / ".rebrew"
        cache_dir.mkdir(exist_ok=True)
        (cache_dir / "verify_cache.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "compiler_hash": "",
                    "headers_hash": "",
                    "target": "GAME",
                    "entries": {
                        f"0x{va:08x}": {
                            "source_hash": "",
                            "filepath": src.name,
                            "mtime_ns": 0,
                            "result": {
                                "status": "NEAR_MATCHING",
                                "va": f"0x{va:08x}",
                                "size": 100,
                                "filepath": src.name,
                                "name": "f",
                                "message": "",
                                "passed": False,
                            },
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        result = self._invoke(proj_dir, src, monkeypatch)
        assert result.exit_code != 0
        # The gate passed (cache said NEAR_MATCHING); any failure is
        # downstream (angr/compile), never the status rejection.
        assert "expected NEAR_MATCHING" not in result.output

    def test_accepts_size_mismatch_status(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SIZE_MISMATCH passes the gate (bytes differ structurally — the
        prove contract) and reaches the pipeline instead of being rejected
        like EXACT/STUB."""
        proj_dir, src = self._make_project(tmp_path, "SIZE_MISMATCH")
        result = self._invoke(proj_dir, src, monkeypatch)
        assert result.exit_code != 0
        # The gate passed; any failure is downstream (angr/compile), never the
        # status rejection.
        assert "expected NEAR_MATCHING" not in result.output

    def test_counterexample_written_to_note(self, tmp_path: Path) -> None:
        """A Z3 counterexample persists as a metadata NOTE for the reverser."""
        from types import SimpleNamespace

        from rebrew.metadata import load_metadata
        from rebrew.prove import _record_prove_counterexample

        cfg = SimpleNamespace(metadata_dir=tmp_path)
        ann = SimpleNamespace(module="GAME", va=0x1000)
        _record_prove_counterexample(
            cfg, ann, "Z3 found a satisfying assignment where EAX differs; EAX=0 vs 4"
        )
        entry = load_metadata(tmp_path).get(("GAME", 0x1000), {})
        assert "prove:" in (entry.get("note") or "")
        assert "EAX=0 vs 4" in entry.get("note", "")

    def test_counterexample_not_written_for_timeout(self, tmp_path: Path) -> None:
        """Timeout/path-explosion messages carry no counterexample — no note."""
        from types import SimpleNamespace

        from rebrew.metadata import load_metadata
        from rebrew.prove import _record_prove_counterexample

        cfg = SimpleNamespace(metadata_dir=tmp_path)
        ann = SimpleNamespace(module="GAME", va=0x1000)
        _record_prove_counterexample(
            cfg, ann, "No terminal states reached for original binary (timeout)"
        )
        assert load_metadata(tmp_path).get(("GAME", 0x1000), {}).get("note") is None

    def test_counterexample_does_not_clobber_existing_note(self, tmp_path: Path) -> None:
        """A reverser's own note is never overwritten by the prove note."""
        from types import SimpleNamespace

        from rebrew.metadata import load_metadata, set_field
        from rebrew.prove import _record_prove_counterexample

        set_field(tmp_path, 0x1000, "note", "mine: hand analysis", module="GAME")
        cfg = SimpleNamespace(metadata_dir=tmp_path)
        ann = SimpleNamespace(module="GAME", va=0x1000)
        _record_prove_counterexample(
            cfg, ann, "Z3 found a satisfying assignment where EAX differs; EAX=1 vs 9"
        )
        entry = load_metadata(tmp_path).get(("GAME", 0x1000), {})
        assert entry.get("note") == "mine: hand analysis"


@pytest.mark.skipif(
    not has_angr,
    reason="angr not installed (run 'uv sync --all-extras' to enable prove tests)",
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
    reason="angr not installed (run 'uv sync --all-extras' to enable prove tests)",
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
    reason="angr not installed (run 'uv sync --all-extras' to enable prove tests)",
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
    reason="angr (and claripy) not installed (run 'uv sync --all-extras' to enable prove tests)",
)
class TestProveEquivalenceCheckEdxMocked:
    """EDX checking verdicts, with ``_run_simulation`` patched to return
    crafted states — the real ``prove_equivalence`` → ``_compare_state_pairs``
    logic (including the EAX+EDX disjunction) is what is under test."""

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

    @pytest.mark.parametrize(
        ("check_edx", "expect_proven", "expect_edx_in_msg"),
        [(True, False, True), (False, True, False)],
    )
    def test_eax_matches_edx_differs_check_edx_behavior(
        self,
        monkeypatch: pytest.MonkeyPatch,
        check_edx: bool,
        expect_proven: bool,
        expect_edx_in_msg: bool,
    ) -> None:
        """EAX matches but EDX differs: rejected when check_edx=True, accepted otherwise."""
        import rebrew.prove as prove_mod

        state_orig = self._make_mock_state(eax_val=42, edx_val=0)
        state_comp = self._make_mock_state(eax_val=42, edx_val=99)  # EDX differs

        # prove_equivalence always simulates orig first, then comp; patch the
        # (now module-level) _run_simulation to hand back crafted states and
        # let the REAL _compare_state_pairs produce the verdict.
        calls = {"n": 0}

        def fake_run_simulation(proj: object, state: object, **kw: object) -> list[object]:
            calls["n"] += 1
            return [state_orig] if calls["n"] == 1 else [state_comp]

        monkeypatch.setattr("rebrew.prove._run_simulation", fake_run_simulation)

        proven, msg = prove_mod.prove_equivalence(
            b"\xc3",
            b"\xc3",
            None,
            "int __cdecl foo(void)",
            check_edx=check_edx,
        )
        assert proven is expect_proven, f"Expected proven={expect_proven} but got: {msg}"
        assert ("EAX+EDX" in msg) is expect_edx_in_msg


class TestPrepareProveInputsDir32:
    """The early-match gate must use the same DIR32 validation as test/verify."""

    def test_early_match_receives_name_to_va(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from types import SimpleNamespace

        import rebrew.prove as pm

        ann = SimpleNamespace(
            va=0x1000,
            size=16,
            cflags="/O2",
            symbol="_f",
            name="f",
            module="SERVER",
            status="NEAR_MATCHING",
            prototype="",
            prove_constraints=None,
        )
        cfg = SimpleNamespace(
            target_binary=tmp_path / "x.dll",
            metadata_dir=tmp_path / "md",
            reversed_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
        )
        (tmp_path / "x.dll").write_bytes(b"\x00" * 64)
        (tmp_path / "md").mkdir()
        src = tmp_path / "f.c"
        src.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")

        captured: dict[str, object] = {}

        def fake_smart_reloc_compare(
            obj: bytes,
            tgt: bytes,
            relocs: object,
            name_to_va: object = None,
            section_va: object = None,
            iat_region: object = None,
        ) -> tuple[bool, int, int, list[int], list[int]]:
            captured["name_to_va"] = name_to_va
            captured["section_va"] = section_va
            captured["iat_region"] = iat_region
            return (False, 0, 0, [], [])  # not matched → proceed to prove

        monkeypatch.setattr(pm, "smart_reloc_compare", fake_smart_reloc_compare)
        monkeypatch.setattr(pm, "build_name_to_va", lambda cfg: {"g_counter": 0x2000})
        monkeypatch.setattr(pm, "build_iat_region", lambda cfg: {0x24178})
        monkeypatch.setattr(pm, "extract_raw_bytes", lambda b, va, size: b"\x00" * 16)
        monkeypatch.setattr(
            pm, "compile_to_obj", lambda cfg, src, cflags, wd, **kw: ("obj.obj", "")
        )
        monkeypatch.setattr(pm, "parse_obj_symbol_bytes", lambda obj, sym: (b"\x00" * 16, {}))
        monkeypatch.setattr(pm, "_resolve_watched_dir32", lambda obj, sym, cfg, ws: {})
        monkeypatch.setattr(pm, "resolve_symbol", lambda ann, src: "_f")

        inputs = pm._prepare_prove_inputs(cfg, src, ann, None)
        assert captured["name_to_va"] == {"g_counter": 0x2000}
        assert captured["section_va"] == 0x1000
        assert captured["iat_region"] == {0x24178}
        assert inputs.symbol == "_f"
        assert inputs.size == 16

    def test_early_match_still_promotes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A genuinely matching function still raises _AlreadyMatched."""
        from types import SimpleNamespace

        import pytest

        import rebrew.prove as pm

        ann = SimpleNamespace(
            va=0x1000,
            size=16,
            cflags="/O2",
            symbol="_f",
            name="f",
            module="SERVER",
            status="NEAR_MATCHING",
            prototype="",
            prove_constraints=None,
        )
        cfg = SimpleNamespace(
            target_binary=tmp_path / "x.dll",
            metadata_dir=tmp_path / "md",
            reversed_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
        )
        (tmp_path / "x.dll").write_bytes(b"\x00" * 64)
        (tmp_path / "md").mkdir()
        src = tmp_path / "f.c"
        src.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")

        monkeypatch.setattr(
            pm,
            "smart_reloc_compare",
            lambda obj, tgt, relocs, name_to_va=None, section_va=None, iat_region=None: (
                True,
                16,
                16,
                [0x1000],
                [],
            ),
        )
        monkeypatch.setattr(pm, "build_name_to_va", lambda cfg: {})
        monkeypatch.setattr(pm, "extract_raw_bytes", lambda b, va, size: b"\x00" * 16)
        monkeypatch.setattr(
            pm, "compile_to_obj", lambda cfg, src, cflags, wd, **kw: ("obj.obj", "")
        )
        monkeypatch.setattr(pm, "parse_obj_symbol_bytes", lambda obj, sym: (b"\x00" * 16, {}))
        monkeypatch.setattr(pm, "_resolve_watched_dir32", lambda obj, sym, cfg, ws: {})
        monkeypatch.setattr(pm, "resolve_symbol", lambda ann, src: "_f")

        with pytest.raises(pm._AlreadyMatched) as excinfo:
            pm._prepare_prove_inputs(cfg, src, ann, None)
        assert excinfo.value.new_status == "RELOC"  # _vr truthy


class TestWatchVaHexParsing:
    def test_hex_watch_va_accepted(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--watch-va accepts hex VAs like every other tool (was int-only)."""
        from types import SimpleNamespace

        from typer.testing import CliRunner

        import rebrew.prove as pm

        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        f = src / "foo.c"
        f.write_text(
            "// FUNCTION: GAME 0x1000\nint __cdecl foo(void) { return 0; }\n", encoding="utf-8"
        )
        (src / "rebrew-functions.toml").write_text(
            '["GAME.0x00001000"]\nstatus = "NEAR_MATCHING"\nsize = 16\n', encoding="utf-8"
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=src,
            marker="GAME",
            source_ext=".c",
            target_binary=tmp_path / "game.exe",
        )
        (tmp_path / "game.exe").write_bytes(b"\x00" * 64)
        monkeypatch.setattr(pm, "_require_angr", lambda: None)
        monkeypatch.setattr(pm, "require_config", lambda target=None, json_mode=False: cfg)
        captured: dict[str, object] = {}

        def fake_prepare(cfg, source_path, ann, watch_va, **kw):
            captured["watch_va"] = watch_va
            raise pm._ProveError("stop-early")

        monkeypatch.setattr(pm, "_prepare_prove_inputs", fake_prepare)
        result = CliRunner().invoke(pm.app, ["--watch-va", "0x10027078", str(f)])
        assert result.exit_code != 0  # stopped early by the fake
        assert captured.get("watch_va") == [0x10027078]


class TestWatchVaValidation:
    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, watch_val: str) -> object:
        from types import SimpleNamespace

        from typer.testing import CliRunner

        import rebrew.prove as pm

        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        f = src / "foo.c"
        f.write_text(
            "// FUNCTION: GAME 0x1000\nint __cdecl foo(void) { return 0; }\n", encoding="utf-8"
        )
        (src / "rebrew-functions.toml").write_text(
            '["GAME.0x00001000"]\nstatus = "NEAR_MATCHING"\nsize = 16\n', encoding="utf-8"
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=src,
            marker="GAME",
            source_ext=".c",
            target_binary=tmp_path / "game.exe",
        )
        (tmp_path / "game.exe").write_bytes(b"\x00" * 64)
        monkeypatch.setattr(pm, "_require_angr", lambda: None)
        monkeypatch.setattr(pm, "require_config", lambda target=None, json_mode=False: cfg)
        called = {"prepare": False}

        def fake_prepare(cfg, source_path, ann, watch_va, **kw):
            called["prepare"] = True
            raise pm._ProveError("stop-early")

        monkeypatch.setattr(pm, "_prepare_prove_inputs", fake_prepare)
        result = CliRunner().invoke(pm.app, ["--watch-va", watch_val, str(f)])
        result.called_prepare = called  # type: ignore[attr-defined]
        return result

    def test_out_of_range_hex_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A watch VA beyond 32 bits is a clean argument error, not a silent no-op."""
        from rebrew.cli import EXIT_ERROR

        result = self._invoke(tmp_path, monkeypatch, "0x1FFFFFFFF")  # type: ignore[attr-defined]
        assert result.exit_code == EXIT_ERROR
        assert "Invalid watch VA" in result.output
        assert not result.called_prepare["prepare"]  # type: ignore[attr-defined]

    def test_decimal_overflow_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """2^32 as a decimal is rejected the same way."""
        from rebrew.cli import EXIT_ERROR

        result = self._invoke(tmp_path, monkeypatch, "4294967296")  # type: ignore[attr-defined]
        assert result.exit_code == EXIT_ERROR
        assert "Invalid watch VA" in result.output
        assert not result.called_prepare["prepare"]  # type: ignore[attr-defined]

    def test_boundary_values_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """0 and 0xFFFFFFFF are the inclusive valid range."""
        from types import SimpleNamespace

        from typer.testing import CliRunner

        import rebrew.prove as pm

        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        f = src / "foo.c"
        f.write_text(
            "// FUNCTION: GAME 0x1000\nint __cdecl foo(void) { return 0; }\n", encoding="utf-8"
        )
        (src / "rebrew-functions.toml").write_text(
            '["GAME.0x00001000"]\nstatus = "NEAR_MATCHING"\nsize = 16\n', encoding="utf-8"
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=src,
            marker="GAME",
            source_ext=".c",
            target_binary=tmp_path / "game.exe",
        )
        (tmp_path / "game.exe").write_bytes(b"\x00" * 64)
        monkeypatch.setattr(pm, "_require_angr", lambda: None)
        monkeypatch.setattr(pm, "require_config", lambda target=None, json_mode=False: cfg)
        captured: dict[str, object] = {}

        def fake_prepare(cfg, source_path, ann, watch_va, **kw):
            captured["watch_va"] = watch_va
            raise pm._ProveError("stop-early")

        monkeypatch.setattr(pm, "_prepare_prove_inputs", fake_prepare)
        result = CliRunner().invoke(pm.app, ["--watch-va", "0", "--watch-va", "0xFFFFFFFF", str(f)])
        assert result.exit_code != 0  # stopped early by the fake
        assert captured.get("watch_va") == [0, 0xFFFFFFFF]


class TestProveInputsWatchedVasMetadata:
    def _prepare(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, meta_vas: object) -> object:
        from types import SimpleNamespace

        import rebrew.prove as pm

        ann = SimpleNamespace(
            va=0x1000,
            size=16,
            cflags="/O2",
            symbol="_f",
            name="f",
            module="SERVER",
            status="NEAR_MATCHING",
            prototype="",
            prove_constraints={"watched_vas": meta_vas},
        )
        cfg = SimpleNamespace(
            target_binary=tmp_path / "x.dll",
            metadata_dir=tmp_path / "md",
            reversed_dir=tmp_path,
            marker="SERVER",
            source_ext=".c",
        )
        (tmp_path / "x.dll").write_bytes(b"\x00" * 64)
        (tmp_path / "md").mkdir()
        src = tmp_path / "f.c"
        src.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")

        monkeypatch.setattr(
            pm,
            "smart_reloc_compare",
            lambda obj, tgt, relocs, name_to_va=None, section_va=None, iat_region=None: (
                False,
                0,
                0,
                [],
                [],
            ),
        )
        monkeypatch.setattr(pm, "build_name_to_va", lambda cfg: {})
        monkeypatch.setattr(pm, "extract_raw_bytes", lambda b, va, size: b"\x00" * 16)
        monkeypatch.setattr(
            pm, "compile_to_obj", lambda cfg, src, cflags, wd, **kw: ("obj.obj", "")
        )
        monkeypatch.setattr(pm, "parse_obj_symbol_bytes", lambda obj, sym: (b"\x00" * 16, {}))
        monkeypatch.setattr(pm, "_resolve_watched_dir32", lambda obj, sym, cfg, ws: {})
        monkeypatch.setattr(pm, "resolve_symbol", lambda ann, src: "_f")
        return pm._prepare_prove_inputs(cfg, src, ann, None)

    def test_valid_metadata_int_and_str_accepted(self, tmp_path: Path, monkeypatch: object) -> None:
        inputs = self._prepare(tmp_path, monkeypatch, [0x2000, "0x3000", 0x4000])  # type: ignore[arg-type]
        assert inputs.watched_vas == [0x2000, 0x3000, 0x4000]

    def test_garbage_metadata_raises(self, tmp_path: Path, monkeypatch: object) -> None:
        import pytest

        import rebrew.prove as pm

        with pytest.raises(pm._ProveError, match="watched_vas"):
            self._prepare(tmp_path, monkeypatch, ["garbage"])  # type: ignore[arg-type]

    def test_out_of_range_metadata_raises(self, tmp_path: Path, monkeypatch: object) -> None:
        import pytest

        import rebrew.prove as pm

        with pytest.raises(pm._ProveError, match="outside 0..0xFFFFFFFF"):
            self._prepare(tmp_path, monkeypatch, [0x100000000])  # type: ignore[arg-type]


class TestWatchVaDecimal:
    def test_decimal_watch_va_accepted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--watch-va decimal form still works (int(v, 0) preserves it)."""
        from types import SimpleNamespace

        from typer.testing import CliRunner

        import rebrew.prove as pm

        src = tmp_path / "src"
        src.mkdir(exist_ok=True)
        f = src / "foo.c"
        f.write_text(
            "// FUNCTION: GAME 0x1000\nint __cdecl foo(void) { return 0; }\n", encoding="utf-8"
        )
        (src / "rebrew-functions.toml").write_text(
            '["GAME.0x00001000"]\nstatus = "NEAR_MATCHING"\nsize = 16\n', encoding="utf-8"
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            reversed_dir=src,
            metadata_dir=src,
            marker="GAME",
            source_ext=".c",
            target_binary=tmp_path / "game.exe",
        )
        (tmp_path / "game.exe").write_bytes(b"\x00" * 64)
        monkeypatch.setattr(pm, "_require_angr", lambda: None)
        monkeypatch.setattr(pm, "require_config", lambda target=None, json_mode=False: cfg)
        captured: dict[str, object] = {}

        def fake_prepare(cfg, source_path, ann, watch_va, **kw):
            captured["watch_va"] = watch_va
            raise pm._ProveError("stop-early")

        monkeypatch.setattr(pm, "_prepare_prove_inputs", fake_prepare)
        result = CliRunner().invoke(pm.app, ["--watch-va", "268574328", str(f)])
        assert result.exit_code != 0
        assert captured.get("watch_va") == [268574328]


class TestMaxDeltaFilter:
    """J4: prove --all --max-delta focuses on the closest near-misses."""

    def _anno(self, va: int, delta: int | None) -> Any:
        from rebrew.annotation import Annotation

        return Annotation(
            va=va,
            name=f"f{va}",
            symbol=f"_f{va}",
            module="T",
            status="NEAR_MATCHING",
            size=10,
            marker_type="FUNCTION",
            filepath="f.c",
            blocker_delta=delta,
        )

    def test_filters_by_blocker_delta(self, tmp_path: Path, monkeypatch, capsys) -> None:
        from rebrew.prove import _run_all_batch

        src = tmp_path / "src"
        src.mkdir()
        (src / "f.c").write_text("// FUNCTION: T 0x1000\n", encoding="utf-8")
        cfg = SimpleNamespace(
            reversed_dir=src,
            metadata_dir=tmp_path,
            root=tmp_path,
            default_jobs=1,
            target_name="T",
            source_ext=".c",
            marker="T",
        )
        annos = [self._anno(0x1000, 2), self._anno(0x2000, 40), self._anno(0x3000, None)]
        monkeypatch.setattr("rebrew.prove.parse_c_file_multi", lambda *a, **k: annos)
        # Capture which candidates reach the proving loop.
        seen: list[int] = []

        def _fake_prove_one(*a, **k):  # type: ignore[no-untyped-def]
            seen.append(0)
            return False

        monkeypatch.setattr("rebrew.prove._prove_single", _fake_prove_one)
        monkeypatch.setattr("rebrew.prove.build_name_to_va", lambda cfg: {})
        _run_all_batch(
            cfg,
            timeout=10,
            loop_bound=5,
            dry_run=True,
            json_output=True,
            max_delta=10,
        )
        # Only the delta-2 candidate (and the unknown-delta one) pass the gate.
        assert len(seen) == 2


@pytest.mark.skipif(
    not has_angr,
    reason="angr not installed (run 'uv sync --all-extras' to enable prove tests)",
)
class TestProveEquivalenceBytes:
    """End-to-end semantic equivalence on synthetic x86-32 blobs.

    Exercises the full angr symbolic-execution path (blob backend, symbolic
    args, Z3 state-pair comparison) without a compiler or target binary —
    the bytes ARE the fixture.  Pins the core verdicts: equivalent
    implementations prove True, differing ones prove False.
    """

    def test_equivalent_different_encodings(self) -> None:
        """mov eax,5;ret vs push 5;pop eax;ret — same semantics, different bytes."""
        a = bytes.fromhex("B8 05 00 00 00 C3")
        b = bytes.fromhex("6A 05 58 C3")
        proven, msg = prove_equivalence(a, b, {}, "int f(void)", timeout=30)
        assert proven, msg

    def test_not_equivalent_constant(self) -> None:
        """mov eax,5;ret vs mov eax,6;ret — Z3 must find the EAX difference."""
        a = bytes.fromhex("B8 05 00 00 00 C3")
        b = bytes.fromhex("B8 06 00 00 00 C3")
        proven, msg = prove_equivalence(a, b, {}, "int f(void)", timeout=30)
        assert not proven
        assert "EAX" in msg or "differs" in msg

    def test_equivalent_register_trick(self) -> None:
        """xor eax,eax;inc eax;ret vs mov eax,1;ret."""
        a = bytes.fromhex("31 C0 40 C3")
        b = bytes.fromhex("B8 01 00 00 00 C3")
        proven, msg = prove_equivalence(a, b, {}, "int f(void)", timeout=30)
        assert proven, msg

    def test_equivalent_identity_argument(self) -> None:
        """mov eax,[esp+4];ret — returns its argument unchanged (identity)."""
        a = bytes.fromhex("8B 44 24 04 C3")
        proven, msg = prove_equivalence(a, a, {}, "int f(int)", timeout=30)
        assert proven, msg


class TestProveCeilingFilter:
    """`rebrew prove --all --ceiling` targets exactly the GA_CEILING set —
    the register-only effective-match functions `rebrew match` documented as
    the prove lane."""

    def _make_project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, list]:
        import shutil

        toml = tmp_path / "rebrew-project.toml"
        toml.write_text(
            '[targets.GAME]\nbinary = "game.exe"\nreversed_dir = "src"\nsource_ext = ".c"\n'
        )
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        ceiling = src_dir / "ceiling.c"
        ceiling.write_text(
            "// FUNCTION: GAME 0x00001000\nint __cdecl ceiling_fn(void) { return 0; }\n"
        )
        plain = src_dir / "plain.c"
        plain.write_text("// FUNCTION: GAME 0x00002000\nint __cdecl plain_fn(void) { return 0; }\n")
        metadata_toml = tmp_path / "rebrew-functions.toml"
        metadata_toml.write_text(
            '["GAME.0x00001000"]\nstatus = "NEAR_MATCHING"\nsize = 16\n'
            'blocker = "GA_CEILING: register-only byte delta (effective match)"\n'
            '["GAME.0x00002000"]\nstatus = "NEAR_MATCHING"\nsize = 16\n'
        )
        shutil.copy(FIXTURES / "mini_pe.exe", tmp_path / "game.exe")
        calls: list[str] = []
        monkeypatch.setattr("rebrew.prove._prove_single", lambda *a, **k: (False, "mocked"))
        return tmp_path, calls

    def test_ceiling_selects_only_documented(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.prove import app

        proj_dir, calls = self._make_project(tmp_path, monkeypatch)
        monkeypatch.chdir(proj_dir)
        result = CliRunner().invoke(
            app, ["--all", "--ceiling", "--json", "--target", "GAME"], catch_exceptions=False
        )
        assert result.exit_code == 0
        assert "ceiling_fn" in result.output
        assert "plain_fn" not in result.output

    def test_all_still_covers_both(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from rebrew.prove import app

        proj_dir, _ = self._make_project(tmp_path, monkeypatch)
        monkeypatch.chdir(proj_dir)
        result = CliRunner().invoke(
            app, ["--all", "--json", "--target", "GAME"], catch_exceptions=False
        )
        assert result.exit_code == 0
        assert "ceiling_fn" in result.output
        assert "plain_fn" in result.output
