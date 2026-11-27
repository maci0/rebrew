"""Lazy round-trip documents must render exactly what a full tomlkit parse would."""

import functools
import tomllib
from collections import OrderedDict
from collections.abc import Callable  # noqa: TC003 - tests keep eager imports
from typing import Any

import pytest
import tomlkit
from tomlkit.exceptions import ParseError

from rebrew.metadata import lazydoc, rendered_toml
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


@pytest.fixture
def no_parsed_records(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty record and split caches, so a test sees which records a parse reads."""
    monkeypatch.setattr(lazydoc, "_RECORDS", OrderedDict())
    monkeypatch.setattr(lazydoc, "_RECORDS_CHARS", 0)
    monkeypatch.setattr(lazydoc, "_SPLITS", OrderedDict())


def _parsed_texts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every text :mod:`rendered_toml` parses from now on."""
    parsed: list[str] = []
    real = rendered_toml.loads

    def loads(text: str) -> dict[str, Any]:
        parsed.append(text)
        return real(text)

    monkeypatch.setattr(rendered_toml, "loads", loads)
    return parsed


@pytest.mark.parametrize(
    ("prefix", "extra", "expect"),
    [
        # A line of a multi-line array that starts with "[" splits the record in two.
        ("", '\n["GAME.0x00000001"]\nvalues = [\n[1, 2],\n]\n', ("GAME.0x00000001", "values")),
        # Dotted keys before the first header define the record a later header extends.
        ('fruit.kind = "x"\n', '\n[fruit.apple]\ncolor = "red"\n', ("fruit", "kind")),
    ],
    ids=["array-line-like-a-header", "preamble-defines-a-record"],
)
def test_records_that_do_not_parse_alone_fall_back_to_full_parse(
    store: str, prefix: str, extra: str, expect: tuple[str, str]
) -> None:
    text = prefix + store + extra
    doc = parse_roundtrip(text)
    assert not isinstance(doc, LazyDocument)
    assert lazydoc.split_records(text) is None
    key, field = expect
    assert doc[key][field] == tomllib.loads(text)[key][field]
    assert lazydoc.loads(text) == tomllib.loads(text)


@pytest.mark.parametrize(
    "extra",
    ['\n["GAME.0x\x01"]\nname = "x"\n', '\n["GAME.0x00000001"]\nname = \n'],
    ids=["control-character-in-header", "missing-value"],
)
def test_invalid_records_raise_the_tomlkit_error(store: str, extra: str) -> None:
    with pytest.raises(ParseError):
        parse_roundtrip(store + extra)


@pytest.mark.usefixtures("no_parsed_records")
def test_records_split_alone_hold_the_whole_document_values(store: str) -> None:
    split = lazydoc.split_records(store)
    assert split is not None
    preamble, head, records = split
    whole = tomllib.loads(store)
    assert head == {"format": 3}
    assert list(head) + [key for key, _raw, _value in records] == list(whole)
    assert {key: value for key, _raw, value in records} == {
        key: value for key, value in whole.items() if key != "format"
    }
    assert preamble + "".join(raw for _key, raw, _value in records) == store


@pytest.mark.usefixtures("no_parsed_records")
def test_an_edited_document_parses_only_the_record_it_changed(
    store: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    lazy = parse_roundtrip(store)
    _edit_existing(lazy)
    edited = render(lazy)
    parsed = _parsed_texts(monkeypatch)
    doc = parse_roundtrip(edited)
    assert isinstance(doc, LazyDocument)
    # The preamble, then the one record the edit re-rendered.
    assert len(parsed) == 2
    assert parsed[1].startswith('["GAME.0x00001010"]')
    whole = tomllib.loads(edited)
    assert all(doc.peek(key) == whole[key] for key in whole if key != "format")
    assert render(doc) == edited


@pytest.mark.usefixtures("no_parsed_records")
def test_loads_copies_the_records_of_a_recent_split(
    store: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    parse_roundtrip(store)
    parsed = _parsed_texts(monkeypatch)
    first = lazydoc.loads(store)
    assert parsed == []
    assert first == tomllib.loads(store)
    assert list(first) == list(tomllib.loads(store))
    first["GAME.0x00001000"]["name"] = "mutated"
    first["GAME.0x00001000"]["status_history"].append({"old_status": "x"})
    assert lazydoc.loads(store) == tomllib.loads(store)
    assert parse_roundtrip(store).peek("GAME.0x00001000")["name"] == "fcn_00000"


@pytest.mark.usefixtures("no_parsed_records")
def test_loads_parses_a_document_no_write_split(
    store: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = _parsed_texts(monkeypatch)
    assert lazydoc.loads(store) == tomllib.loads(store)
    assert parsed == [store]


def test_small_documents_use_a_full_parse() -> None:
    doc = parse_roundtrip('format = 3\n\n["GAME.0x1000"]\nname = "a"\n')
    assert isinstance(doc, tomlkit.TOMLDocument)


def test_peek_reads_untouched_records_without_parsing_them(store: str) -> None:
    lazy = parse_roundtrip(store)
    assert isinstance(lazy, LazyDocument)
    full = tomlkit.parse(store)
    for key in full:
        if key != "format":
            assert lazy.peek(key) == full[key].unwrap()
    assert all(chunk.doc is None for chunk in lazy._chunks)
    assert lazydoc.peek(lazy, "GAME.0x00001010")["name"] == "fcn_00001"


def test_peek_sees_edits_made_through_the_document(store: str) -> None:
    lazy = parse_roundtrip(store)
    _edit_existing(lazy)
    _add_record(lazy)
    _delete_record(lazy)
    assert lazy.peek("GAME.0x00001010")["status"] == "EXACT"
    assert lazy.peek("GAME.0x00001010")["blocker"] == "new field"
    assert lazy.peek("GAME.0x7fff0000")["name"] == "added"
    with pytest.raises(KeyError):
        lazy.peek("GAME.0x00001020")


def test_peek_on_a_full_document_is_plain_item_access() -> None:
    doc = tomlkit.parse('["GAME.0x1000"]\nname = "f"\n')
    assert lazydoc.peek(doc, "GAME.0x1000")["name"] == "f"
