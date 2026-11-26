"""Round-trip TOML documents whose top-level records are parsed only when touched.

A single-record edit of a large metadata store used to parse the whole file
with tomlkit (about 18 s for a 21 MB function store) and dump all of it again.
:func:`parse_roundtrip` splits the text at top-level table headers, keeps each
record's text verbatim, and gives tomlkit only the records a writer touches;
:func:`render` writes untouched records back unchanged.  Validation runs on a
``tomllib`` parse of the same text.  Text the splitter cannot segment exactly
(multi-line strings, a record split across non-adjacent headers, keys that
disagree with ``tomllib``) falls back to a full tomlkit parse.
"""

from collections.abc import Callable, Iterator, MutableMapping
from typing import Any, cast, override
lazy import tomllib

lazy import tomlkit
lazy from tomlkit import TOMLDocument
lazy from tomlkit.items import Item

#: Below this size a full tomlkit parse is cheap and keeps the plain path.
LAZY_MIN_CHARS = 256 * 1024

_BARE_KEY_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")


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


def parse_roundtrip(
    text: str, validate: Callable[[dict[str, Any]], Any] | None = None
) -> dict[str, Any]:
    """Parse *text* for round-trip editing, validating a plain ``tomllib`` view.

    Returns a :class:`LazyDocument` for a large document the splitter can segment
    exactly, else a full ``TOMLDocument``.  A ``tomllib`` decode error falls back to
    tomlkit so callers keep tomlkit's error type and message.
    """
    if len(text) < LAZY_MIN_CHARS:
        doc = tomlkit.parse(text)
        if validate is not None:
            validate(doc)
        return doc
    segmented = _segment(text)
    try:
        plain = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        segmented = None
        plain = {}
    if segmented is not None:
        preamble, chunks = segmented
        lazy = LazyDocument(preamble, chunks, plain)
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
