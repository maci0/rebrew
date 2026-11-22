"""Lazy round-trip documents must render exactly what a full tomlkit parse would."""

import functools
from collections.abc import Callable  # noqa: TC003 - tests keep eager imports
from typing import Any

import pytest
import tomlkit

from rebrew.metadata import lazydoc
from rebrew.metadata.lazydoc import LAZY_MIN_CHARS, LazyDocument, parse_roundtrip, render

#: Every store record renders to at least this many characters.
_RECORD_CHARS_MIN = 230
#: ``LAZY_MIN_CHARS`` patched in where a test compares the lazy path with a
#: full parse; the real threshold is exercised by test_validation_sees_every_record.
_TEST_LAZY_MIN_CHARS = 8 * 1024


def _records_over(min_chars: int) -> int:
    """Records a store needs to reach *min_chars* characters."""
    return min_chars // _RECORD_CHARS_MIN + 1


@functools.cache
def _store_text(records: int) -> str:
    doc = tomlkit.document()
    doc["format"] = 3
    for index in range(records):
        key = f"GAME.0x{0x1000 + index * 16:08x}"
        entry = tomlkit.table()
        entry["name"] = f"fcn_{index:05x}"
        entry["status"] = "RELOC"
        entry["note"] = 'quoted "text" with \\ backslash'
        verification = tomlkit.table()
        verification["aligned_pairs"] = index
        entry["verification"] = verification
        history = tomlkit.aot()
        row = tomlkit.table()
        row["old_status"] = "STUB"
        row["new_status"] = "RELOC"
        history.append(row)
        entry["status_history"] = history
        doc[key] = entry
    return tomlkit.dumps(doc)


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> str:
    """A store over :data:`_TEST_LAZY_MIN_CHARS`, patched in as ``LAZY_MIN_CHARS``."""
    monkeypatch.setattr(lazydoc, "LAZY_MIN_CHARS", _TEST_LAZY_MIN_CHARS)
    text = _store_text(_records_over(_TEST_LAZY_MIN_CHARS))
    assert len(text) >= _TEST_LAZY_MIN_CHARS
    return text


def _edit_existing(doc: Any) -> None:
    entry = doc["GAME.0x00001010"]
    entry["status"] = "EXACT"
    entry["blocker"] = "new field"
    entry["verification"]["aligned_pairs"] = 99


def _add_record(doc: Any) -> None:
    table = tomlkit.table()
    table["name"] = "added"
    doc["GAME.0x7fff0000"] = table


def _delete_record(doc: Any) -> None:
    del doc["GAME.0x00001020"]


def _append_history(doc: Any) -> None:
    row = tomlkit.table()
    row["old_status"] = "RELOC"
    row["new_status"] = "EXACT"
    doc["GAME.0x00001030"]["status_history"].append(row)


def _stamp_format(doc: Any) -> None:
    doc["format"] = 3


EDITS: list[Callable[[Any], None]] = [
    _edit_existing,
    _add_record,
    _delete_record,
    _append_history,
    _stamp_format,
]


@pytest.mark.parametrize("edit", EDITS, ids=lambda edit: edit.__name__)
def test_lazy_edit_renders_like_full_parse(store: str, edit: Callable[[Any], None]) -> None:
    text = store
    lazy = parse_roundtrip(text)
    assert isinstance(lazy, LazyDocument)
    full = tomlkit.parse(text)
    edit(lazy)
    edit(full)
    assert render(lazy) == tomlkit.dumps(full)


def test_all_edits_together_render_like_full_parse(store: str) -> None:
    text = store
    lazy = parse_roundtrip(text)
    full = tomlkit.parse(text)
    for edit in EDITS:
        edit(lazy)
        edit(full)
    assert render(lazy) == tomlkit.dumps(full)


def test_untouched_document_renders_verbatim_and_iterates_in_order(store: str) -> None:
    text = store
    lazy = parse_roundtrip(text)
    assert render(lazy) == text
    full = tomlkit.parse(text)
    assert list(lazy) == list(full)
    assert len(lazy) == len(full)
    assert "GAME.0x00001000" in lazy
    assert lazy.get("GAME.0x00001000")["name"] == "fcn_00000"


def test_validation_sees_every_record() -> None:
    records = _records_over(LAZY_MIN_CHARS)
    text = _store_text(records)
    assert len(text) >= LAZY_MIN_CHARS
    seen: list[int] = []
    doc = parse_roundtrip(text, lambda plain: seen.append(len(plain)))
    assert isinstance(doc, LazyDocument)
    assert seen == [records + 1]


@pytest.mark.parametrize(
    "extra",
    [
        '\n["GAME.0x00000001"]\ntext = """\n[not a header]\n"""\n',
        '\n["GAME.0x00001000".late]\nvalue = 1\n',
    ],
    ids=["multi-line-string", "non-contiguous-record"],
)
def test_unsplittable_text_falls_back_to_full_parse(store: str, extra: str) -> None:
    doc = parse_roundtrip(store + extra)
    assert not isinstance(doc, LazyDocument)
    assert isinstance(doc, tomlkit.TOMLDocument)


def test_small_documents_use_a_full_parse() -> None:
    doc = parse_roundtrip('format = 3\n\n["GAME.0x1000"]\nname = "a"\n')
    assert isinstance(doc, tomlkit.TOMLDocument)
