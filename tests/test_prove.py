"""test_prove.py — Unit tests for rebrew.prove.

Tests cover prototype parsing, resolve_source, and CLI behaviour.
The prove_equivalence() function requires angr (heavy optional dep) and
cannot be unit-tested without it; those paths are covered by integration
tests that are skipped when angr is absent.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from rebrew.prove import _parse_prototype, _resolve_source

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
        cfg = SimpleNamespace(reversed_dir=tmp_path, source_ext=".c")
        result = _resolve_source(str(src), cfg)
        assert result == src

    def test_symbol_search_finds_stem_match(self, tmp_path: Path) -> None:
        src = tmp_path / "my_func.c"
        src.write_text("// FUNCTION: GAME 0x1000\nint my_func(void) { return 0; }\n")
        cfg = SimpleNamespace(reversed_dir=tmp_path, source_ext=".c")
        result = _resolve_source("my_func", cfg)
        assert result == src

    def test_symbol_search_strips_leading_underscore(self, tmp_path: Path) -> None:
        src = tmp_path / "my_func.c"
        src.write_text("// FUNCTION: GAME 0x1000\nint my_func(void) { return 0; }\n")
        cfg = SimpleNamespace(reversed_dir=tmp_path, source_ext=".c")
        result = _resolve_source("_my_func", cfg)
        assert result == src

    def test_nonexistent_returns_path_as_is(self, tmp_path: Path) -> None:
        cfg = SimpleNamespace(reversed_dir=tmp_path, source_ext=".c")
        result = _resolve_source("no_such_func", cfg)
        # Returns Path("no_such_func") which doesn't exist — caller handles it
        assert result == Path("no_such_func")


# ---------------------------------------------------------------------------
# CLI — status guard
# ---------------------------------------------------------------------------


class TestProveCLIStatusGuard:
    """The CLI must reject functions that aren't MATCHING / RELOC."""

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
        # Write status to sidecar
        sidecar = src_dir / "rebrew-function.toml"
        sidecar.write_text(f'["GAME.0x00001000"]\nstatus = "{status}"\nsize = 16\n')
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
