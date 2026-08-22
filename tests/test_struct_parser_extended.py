"""Tests for struct_parser — tree-sitter-absent and unreadable-file branches."""

from pathlib import Path

import pytest

from rebrew.struct_parser import _iter_definitions, get_ts_parser


def test_parser_unavailable_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a: object, **k: object) -> object:
        raise ImportError("no tree-sitter")

    monkeypatch.setattr("rebrew.c_parser._get_parser", _boom)
    assert get_ts_parser() is None


def test_unreadable_file_yields_nothing(tmp_path: Path) -> None:
    # A *.c entry that is actually a directory → read_bytes raises OSError.
    (tmp_path / "bad.c").mkdir()
    assert list(_iter_definitions(tmp_path / "bad.c", all_type_defs=True)) == []


def test_missing_file_yields_nothing(tmp_path: Path) -> None:
    assert list(_iter_definitions(tmp_path / "nope.c", all_type_defs=True)) == []


def test_extracts_typedef_struct(tmp_path: Path) -> None:
    f = tmp_path / "types.h"
    f.write_text("typedef struct { int x; } MyThing;\n", encoding="utf-8")
    defs = list(_iter_definitions(f, all_type_defs=False))
    assert any("MyThing" in d for d in defs)
