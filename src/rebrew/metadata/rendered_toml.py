"""``tomllib.loads`` for metadata documents, fast on the layout rebrew writes.

``tomllib`` reads one character at a time in Python: a 25 MB functions
document (guild-rebrew, 803,420 lines) took about 4.5 s, paid by every command
after any edit. A rendered metadata document is one table header or one
``key = value`` per line, so :func:`loads` reads it a line at a time and
returns exactly what ``tomllib.loads`` returns, in the same key order.

The fast path accepts only lines whose meaning it can decide without TOML's
full grammar: blank lines, ``[a."b".c]`` and ``[[a.b]]`` headers of bare or
unescaped quoted keys, and ``key = value`` with one such key. A basic string
without escapes, or whose only escapes are ``\\"`` and ``\\\\``, a decimal
integer or float, and ``true``/``false`` are converted here; any other value on
the line (a static array, a date, an escape) goes to ``tomllib`` on its own.
Anything else (a comment, ``\\r``, indentation, a dotted key on a value line, a
redefined key or table, a header through a value or a static array, an inline
table, a value spanning lines) hands the whole text to ``tomllib``, so an
invalid document fails exactly as before.
"""

from __future__ import annotations

import json
import re
import tomllib
from typing import Any
lazy from collections.abc import Callable
lazy from functools import lru_cache
lazy from typing import cast

_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)")
_FLOAT = re.compile(r"-?(?:0|[1-9][0-9]*)\.[0-9]+(?:[eE][+-]?[0-9]+)?")
#: Characters TOML forbids unescaped in a basic string or quoted key (tab is allowed).
_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
#: The two escapes JSON and TOML decode the same way; any other goes to ``tomllib``.
_ONLY_QUOTE_ESCAPES = re.compile(r'(?:[^"\\]|\\["\\])*')


class _Fallback(Exception):
    """The text needs ``tomllib``'s full grammar."""


def loads(text: str) -> dict[str, Any]:
    """``tomllib.loads(text)``: the same document, or the same ``TOMLDecodeError``."""
    try:
        return _parse(text)
    except _Fallback:
        return tomllib.loads(text)


def _key(literal: str) -> str:
    """One bare or unescaped quoted key."""
    if _BARE_KEY.fullmatch(literal):
        return literal
    if len(literal) >= 2 and literal[0] == '"' and literal[-1] == '"':
        inner = literal[1:-1]
        if '"' not in inner and "\\" not in inner and not _CONTROL.search(inner):
            return inner
    raise _Fallback


def _path(text: str, key: Callable[[str], str]) -> list[str]:
    """A dotted header path: bare or unescaped quoted keys, no whitespace."""
    keys: list[str] = []
    position = 0
    while True:
        if text.startswith('"', position):
            end = text.find('"', position + 1)
            if end < 0:
                raise _Fallback
            end += 1
        else:
            dot = text.find(".", position)
            end = len(text) if dot < 0 else dot
        keys.append(key(text[position:end]))
        if end == len(text):
            return keys
        if text[end] != ".":
            raise _Fallback
        position = end + 1


def _scalar(literal: str) -> str | int | float | bool | None:
    if (
        len(literal) >= 2
        and literal[0] == '"'
        and literal[-1] == '"'
        and not literal.startswith('"""')
    ):
        inner = literal[1:-1]
        if not _CONTROL.search(inner):
            if "\\" not in inner and '"' not in inner:
                return inner
            if _ONLY_QUOTE_ESCAPES.fullmatch(inner):
                return cast("str", json.loads(literal))
    elif _INTEGER.fullmatch(literal):
        return int(literal)
    elif _FLOAT.fullmatch(literal):
        return float(literal)
    elif literal == "true":
        return True
    elif literal == "false":
        return False
    return None


def _other_value(literal: str) -> Any:
    # One value with the rest of TOML's grammar (an escape, a date, an array, a
    # trailing comment). A value that does not parse alone needs the
    # document's context. An inline table does too: a later header must not
    # extend it, and descend() would. A static array is safe: it never joins
    # ``arrays``, so a header that extends or enters it falls back.
    try:
        value = tomllib.loads(f"v = {literal}")["v"]
    except tomllib.TOMLDecodeError:
        raise _Fallback from None
    if isinstance(value, dict):
        raise _Fallback
    return value


def _parse(text: str) -> dict[str, Any]:
    if "\r" in text:
        raise _Fallback
    root: dict[str, Any] = {}
    current = root
    # Field names and parts of nearby headers repeat.
    key_at = lru_cache(maxsize=128)(_key)
    # Only immutable values can be shared between rows.
    scalar = lru_cache(maxsize=4096)(_scalar)
    #: Tables a ``[header]`` declared, and arrays ``[[header]]`` made, by id.
    declared: set[int] = set()
    arrays: set[int] = set()

    def descend(keys: list[str]) -> dict[str, Any]:
        """The table *keys* name, creating implicit tables on the way."""
        table = root
        for key in keys:
            child = table.get(key)
            if child is None:
                child = table[key] = {}
            elif isinstance(child, list) and id(child) in arrays:
                child = child[-1]
            elif not isinstance(child, dict):
                raise _Fallback
            table = child
        return table

    for line in text.split("\n"):
        if not line:
            continue
        if line[0] == "[":
            if line.startswith("[["):
                if not line.endswith("]]"):
                    raise _Fallback
                *parents, last = _path(line[2:-2], key_at)
                parent = descend(parents)
                existing = parent.get(last)
                if existing is None:
                    existing = parent[last] = []
                    arrays.add(id(existing))
                elif not (isinstance(existing, list) and id(existing) in arrays):
                    raise _Fallback
                current = {}
                existing.append(current)
                declared.add(id(current))
                continue
            if not line.endswith("]"):
                raise _Fallback
            *parents, last = _path(line[1:-1], key_at)
            parent = descend(parents)
            existing = parent.get(last)
            if existing is None:
                current = parent[last] = {}
            elif isinstance(existing, dict) and id(existing) not in declared:
                current = existing
            else:
                raise _Fallback
            declared.add(id(current))
            continue
        if line[0] == '"':
            close = line.find('"', 1)
            if close < 0 or not line.startswith(" = ", close + 1):
                raise _Fallback
            key, literal = key_at(line[: close + 1]), line[close + 4 :]
        else:
            raw_key, separator, literal = line.partition(" = ")
            if not separator:
                raise _Fallback
            key = key_at(raw_key)
        if key in current:
            raise _Fallback
        value = scalar(literal)
        current[key] = _other_value(literal) if value is None else value
    return root
