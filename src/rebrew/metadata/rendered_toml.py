"""Fast TOML loader for metadata documents backed by ``rtoml``.

``tomllib`` parses in pure Python; ``rtoml`` delegates to Rust's ``toml``
parser and runs several times faster on large metadata stores while preserving
insertion key order and Python scalar types.  On a parse failure (or any
document ``rtoml`` rejects), :func:`loads` falls back to ``tomllib.loads`` so
callers receive the exact ``tomllib.TOMLDecodeError`` contract.
"""

from __future__ import annotations

from typing import Any
lazy import tomllib

lazy import rtoml


def loads(text: str) -> dict[str, Any]:
    """Parse TOML *text* via ``rtoml`` with ``tomllib`` error parity."""
    try:
        return rtoml.loads(text)
    except rtoml.TomlParsingError:
        return tomllib.loads(text)
