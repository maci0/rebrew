"""Integration tests for ELF .o parsing via a real gcc-compiled object file."""

import shutil
import subprocess
from pathlib import Path

import pytest

from rebrew.matcher.parsers import (
    list_obj_symbols,
    parse_obj_relocs_full,
    parse_obj_symbol_bytes,
)

_CC = shutil.which("cc") or shutil.which("gcc")

pytestmark = pytest.mark.skipif(_CC is None, reason="no C compiler available")


def _compile(tmp_path: Path) -> Path:
    src = tmp_path / "sample.c"
    src.write_text(
        "int helper(int x) { return x + 1; }\nint caller(int y) { return helper(y) + 2; }\n",
        encoding="utf-8",
    )
    obj = tmp_path / "sample.o"
    subprocess.run([_CC, "-c", "-O0", "-o", str(obj), str(src)], check=True, capture_output=True)
    return obj


class TestElfObjParsing:
    def test_symbol_bytes_extracted(self, tmp_path: Path) -> None:
        obj = _compile(tmp_path)
        code, relocs = parse_obj_symbol_bytes(str(obj), "helper")
        assert code is not None and len(code) > 0
        # helper makes no calls — no relocations expected.
        assert not relocs

    def test_caller_has_call_reloc(self, tmp_path: Path) -> None:
        obj = _compile(tmp_path)
        code, relocs = parse_obj_symbol_bytes(str(obj), "caller")
        assert code is not None and len(code) > 0
        # caller() calls helper() → at least one REL32 relocation.
        assert relocs and any("helper" in sym for sym in relocs.values())

    def test_missing_symbol_returns_none(self, tmp_path: Path) -> None:
        obj = _compile(tmp_path)
        code, relocs = parse_obj_symbol_bytes(str(obj), "no_such_fn")
        assert code is None
        assert relocs is None

    def test_list_symbols(self, tmp_path: Path) -> None:
        obj = _compile(tmp_path)
        syms = list_obj_symbols(str(obj))
        assert "helper" in syms
        assert "caller" in syms

    def test_relocs_full_is_coff_only(self, tmp_path: Path) -> None:
        # parse_obj_relocs_full is COFF-only; ELF call relocs surface via the
        # reloc_offsets dict from parse_obj_symbol_bytes (see caller test).
        obj = _compile(tmp_path)
        assert parse_obj_relocs_full(str(obj), "caller") == []
