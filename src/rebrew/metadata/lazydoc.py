"""Round-trip TOML documents whose top-level records are parsed only when touched.

A single-record edit of a large metadata store used to parse the whole file
with tomlkit (about 18 s for a 21 MB function store) and dump all of it again.
:func:`parse_roundtrip` splits the text at top-level table headers, keeps each
record's text verbatim, and gives tomlkit only the records a writer touches;
:func:`render` writes untouched records back unchanged.  Validation runs on the
``tomllib`` values of the records, each parsed on its own (:func:`split_records`).
Text the splitter cannot segment exactly (multi-line strings, a record split
across non-adjacent headers, a record whose own parse fails or names other keys)
falls back to a full tomlkit parse.
"""

import threading
from collections import OrderedDict
from collections.abc import Callable, Iterator, MutableMapping
from typing import Any, cast, override
lazy import tomllib

lazy import tomlkit
lazy from tomlkit import TOMLDocument
lazy from tomlkit.items import Item

lazy from rebrew.metadata import rendered_toml
lazy from rebrew.utils import clone_plain

#: Below this size a full tomlkit parse is cheap and keeps the plain path.
LAZY_MIN_CHARS = 256 * 1024

_BARE_KEY_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")

#: A document split at its top-level records: preamble text, preamble values and
#: ``(key, record text, value)`` per record, in document order.
Split = tuple[str, dict[str, Any], tuple[tuple[str, str, Any], ...]]

#: Parsed top-level records by their exact text: ``text -> (text, value)``.  A
#: store write re-renders only the records it touched, so parsing the next
#: version of a document in the same process parses only those.  The bound is
#: in characters and must exceed the largest store (guild-rebrew's functions
#: store is 25 MB), or one pass over it evicts each record before its reuse.
_RECORDS: OrderedDict[str, tuple[str, Any]] = OrderedDict()
_RECORDS_CHARS = 0
_RECORDS_MAX_CHARS = 64 * 1024 * 1024
_RECORDS_LOCK = threading.Lock()
#: The last documents split, by their full text: a write splits its new text for
#: the replication digest, and the reads and the next write of that version
#: reuse the split instead of segmenting 25 MB again.
_SPLITS: OrderedDict[str, Split] = OrderedDict()
_SPLITS_MAX = 4


class _Chunk:
    __slots__ = ("doc", "keys", "raw")

    def __init__(self, raw: str, key: str) -> None:
        self.raw = raw
        self.keys = [key]
        self.doc: TOMLDocument | None = None

    def parsed(self) -> TOMLDocument:
        if self.doc is None:
            self.doc = tomlkit.parse(self.raw)
        return self.doc


class LazyDocument(MutableMapping[str, Any]):
    """A TOML document whose top-level tables are tomlkit-parsed on first access."""

    def __init__(self, preamble: str, chunks: list[_Chunk], plain: dict[str, Any]) -> None:
        self._preamble = tomlkit.parse(preamble)
        self._chunks = chunks
        self._index = {key: chunk for chunk in chunks for key in chunk.keys}
        self._plain = plain

    def peek(self, key: str) -> Any:
        """Read-only view of a top-level record that parses nothing for an untouched one.

        An untouched record answers from the ``tomllib`` values read at load; a record
        already parsed for writing answers from its tomlkit table. Callers must not
        mutate the result: edits go through ``doc[key]``.
        """
        chunk = self._index.get(key)
        if chunk is None or chunk.doc is not None:
            return self[key]
        return self._plain[key]

    @override
    def __getitem__(self, key: str) -> Any:
        if key in self._preamble:
            return self._preamble[key]
        return self._index[key].parsed()[key]

    @override
    def __setitem__(self, key: str, value: Any) -> None:
        if key in self._preamble:
            self._preamble[key] = value
        elif key in self._index:
            self._index[key].parsed()[key] = value
        elif not isinstance(value, dict):
            # tomlkit places a new scalar before the first table.
            self._preamble[key] = value
        else:
            # tomlkit appends a new table after the last item; parsing the last
            # record with it reproduces the separator tomlkit would choose.
            if not self._chunks:
                self._chunks.append(_Chunk("", key))
                self._chunks[-1].doc = tomlkit.document()
            else:
                self._chunks[-1].keys.append(key)
            tail = self._chunks[-1]
            tail.parsed()[key] = value
            self._index[key] = tail

    @override
    def __delitem__(self, key: str) -> None:
        if key in self._preamble:
            del self._preamble[key]
            return
        chunk = self._index.pop(key)
        chunk.keys.remove(key)
        if chunk.keys:
            del chunk.parsed()[key]
        else:
            self._chunks.remove(chunk)

    @override
    def __iter__(self) -> Iterator[str]:
        yield from self._preamble
        for chunk in self._chunks:
            yield from chunk.keys

    @override
    def __len__(self) -> int:
        return len(self._preamble) + len(self._index)

    @override
    def __contains__(self, key: object) -> bool:
        return key in self._preamble or key in self._index

    def unwrap(self) -> dict[str, Any]:
        """Plain Python values, like ``TOMLDocument.unwrap``."""
        return {
            key: value.unwrap() if isinstance(value, Item) else value for key, value in self.items()
        }

    def render(self) -> str:
        """The document text: untouched records verbatim, touched records re-dumped."""
        parts = [tomlkit.dumps(self._preamble)]
        for chunk in self._chunks:
            parts.append(chunk.raw if chunk.doc is None else tomlkit.dumps(chunk.doc))
        return "".join(parts)


def _first_key(header: str) -> str | None:
    """The first dotted component of a table header body, or None if unparsable."""
    text = header.lstrip(" \t")
    if not text:
        return None
    quote = text[0]
    if quote in "\"'":
        end = text.find(quote, 1)
        # Without an escape the key is the quoted text. A control character in
        # it fails the record's own parse, so the document still falls back.
        if end > 0 and (quote == "'" or "\\" not in text[1:end]):
            return text[1:end]
        end = 1
        while end < len(text):
            char = text[end]
            if quote == '"' and char == "\\":
                end += 2
                continue
            if char == quote:
                break
            end += 1
        else:
            return None
        try:
            return str(tomllib.loads(f"k = {text[: end + 1]}")["k"])
        except tomllib.TOMLDecodeError:
            return None
    end = 0
    while end < len(text) and text[end] in _BARE_KEY_CHARS:
        end += 1
    return text[:end] or None


def _segment(text: str) -> tuple[str, list[_Chunk]] | None:
    """Split at top-level headers; None when the text cannot be split exactly."""
    if '"""' in text or "'''" in text:
        return None
    lines = text.splitlines(keepends=True)
    preamble: list[str] = []
    chunks: list[_Chunk] = []
    current: list[str] = []
    key = ""
    seen: set[str] = set()
    for line in lines:
        stripped = line.lstrip(" \t")
        if stripped.startswith("["):
            body = stripped[2:] if stripped.startswith("[[") else stripped[1:]
            first = _first_key(body)
            if first is None:
                return None
            if first != key:
                if key:
                    chunks.append(_Chunk("".join(current), key))
                elif current:
                    preamble = current
                if first in seen:
                    return None
                seen.add(first)
                key, current = first, []
        current.append(line)
    if key:
        chunks.append(_Chunk("".join(current), key))
    else:
        preamble = current
    return "".join(preamble), chunks


def split_records(text: str) -> Split | None:
    """*text* split at its top-level records: preamble, its values, ``(key, text, value)`` each.

    Every value is what ``tomllib.loads(text)`` holds under its key. A record is
    parsed on its own, once per process for each exact text; values are shared
    between calls and must not be mutated. None when the text cannot be split
    exactly: a piece fails its own parse (a value spanning a split line leaves one
    piece unterminated), a record parses to other keys, or the preamble defines
    a record's key.
    """
    with _RECORDS_LOCK:
        split = _SPLITS.get(text)
        if split is not None:
            _SPLITS.move_to_end(text)
            return split
    split = _split(text)
    if split is not None:
        with _RECORDS_LOCK:
            _SPLITS[text] = split
            while len(_SPLITS) > _SPLITS_MAX:
                _SPLITS.popitem(last=False)
    return split


def _split(text: str) -> Split | None:
    global _RECORDS_CHARS
    segmented = _segment(text)
    if segmented is None:
        return None
    preamble, chunks = segmented
    try:
        head = rendered_toml.loads(preamble)
    except tomllib.TOMLDecodeError:
        return None
    with _RECORDS_LOCK:
        known = [_RECORDS.get(chunk.raw) for chunk in chunks]
    records: list[tuple[str, str, Any]] = []
    parsed: list[tuple[str, Any]] = []
    for chunk, record in zip(chunks, known, strict=True):
        key = chunk.keys[0]
        if key in head:
            return None
        if record is None:
            try:
                values = rendered_toml.loads(chunk.raw)
            except tomllib.TOMLDecodeError:
                return None
            if list(values) != [key]:
                return None
            record = (chunk.raw, values[key])
            parsed.append(record)
        records.append((key, *record))
    with _RECORDS_LOCK:
        for record in known:
            if record is not None and record[0] in _RECORDS:
                _RECORDS.move_to_end(record[0])
        for raw, value in parsed:
            if raw not in _RECORDS:
                _RECORDS[raw] = (raw, value)
                _RECORDS_CHARS += len(raw)
        while _RECORDS_CHARS > _RECORDS_MAX_CHARS:
            evicted, _ = _RECORDS.popitem(last=False)
            _RECORDS_CHARS -= len(evicted)
    return preamble, head, tuple(records)


def loads(text: str) -> dict[str, Any]:
    """``tomllib.loads(text)``, copied from :func:`split_records` when it split *text* recently.

    A store write splits its new text (for the replication digest or its own
    parse), so the reads of the version it wrote copy record values instead of
    parsing the whole document.  The result is the caller's to mutate.
    """
    split = None
    if len(text) >= LAZY_MIN_CHARS:
        with _RECORDS_LOCK:
            split = _SPLITS.get(text)
            if split is not None:
                _SPLITS.move_to_end(text)
    if split is None:
        return rendered_toml.loads(text)
    _preamble, head, records = split
    doc = {key: clone_plain(value) for key, value in head.items()}
    for key, _raw, value in records:
        doc[key] = clone_plain(value)
    return doc


def parse_roundtrip(
    text: str, validate: Callable[[dict[str, Any]], Any] | None = None
) -> dict[str, Any]:
    """Parse *text* for round-trip editing, validating a plain ``tomllib`` view.

    Returns a :class:`LazyDocument` for a large document the splitter can segment
    exactly, else a full ``TOMLDocument``.  Text that is not valid TOML falls back
    to tomlkit so callers keep tomlkit's error type and message.  The plain view's
    values come from :func:`split_records` and are shared: validators read them.
    """
    if len(text) < LAZY_MIN_CHARS:
        doc = tomlkit.parse(text)
        if validate is not None:
            validate(doc)
        return doc
    split = split_records(text)
    if split is not None:
        preamble, head, records = split
        plain = dict(head)
        plain.update((key, value) for key, _raw, value in records)
        lazy = LazyDocument(preamble, [_Chunk(raw, key) for key, raw, _value in records], plain)
        if list(lazy) == list(plain):
            if validate is not None:
                validate(plain)
            # Store reads are typed as dicts; writers use only mapping operations,
            # which LazyDocument implements, and render() serializes it.
            return cast("dict[str, Any]", lazy)
    doc = tomlkit.parse(text)
    if validate is not None:
        validate(doc)
    return doc


def render(doc: Any) -> str:
    """Render a round-trip document, writing a :class:`LazyDocument`'s untouched records verbatim."""
    if isinstance(doc, LazyDocument):
        return doc.render()
    return tomlkit.dumps(doc)


def peek(doc: Any, key: str) -> Any:
    """Read-only record *key* of a round-trip document; see :meth:`LazyDocument.peek`."""
    return doc.peek(key) if isinstance(doc, LazyDocument) else doc[key]
