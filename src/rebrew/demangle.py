"""demangle.py — MSVC mangled-symbol helpers (reccmp-adapted subset).

Adapted from reccmp (isledecomp/reccmp, MIT License) ``cvdump/demangler.py``.

Scoped port: the pieces that need no full demangler — string-constant
symbol decoding (``??_C@_...``), encoded-length parsing, and vtable symbol
class-name extraction via a self-contained parser for the simple/template
cases.  Full MSVC demangling needs ``pydemumble``; when it is installed
:func:`msvc_demangle` uses it, otherwise it falls back to a minimal
decorator-strip that covers plain C symbols.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from rebrew.errors import RebrewError

# ---------------------------------------------------------------------------


class InvalidEncodedNumberError(RebrewError, Exception):
    """An ``@``-terminated length encoding that is not valid hex-ish A-P."""


_encoded_number_translate = str.maketrans("ABCDEFGHIJKLMNOP", "0123456789ABCDEF")
_HEX_DIGITS = frozenset("0123456789ABCDEF")


def parse_encoded_number(string: str) -> int:
    """Parse an MSVC encoded length (decimal digits or A-P hex letters)."""
    if string.endswith("@"):
        string = string[:-1]
    digits = string.translate(_encoded_number_translate)
    # int(_, 16) alone also takes a sign, whitespace, `_`, and a `0x` prefix.
    if not digits or not _HEX_DIGITS.issuperset(digits):
        raise InvalidEncodedNumberError(string)
    return int(digits, 16)


_string_const_regex = re.compile(
    r"\?\?_C@\_(?P<is_utf16>[0-1])(?P<len>\d|[A-P]+@)(?P<hash>\w+)@(?P<value>.+)@"
)


@dataclass(frozen=True)
class StringConstInfo:
    """Shape decoded from a ``??_C@_`` string-constant symbol."""

    length: int
    is_utf16: bool


def demangle_string_const(symbol: str) -> StringConstInfo | None:
    """Decode length/width from a string-const symbol name.

    The text itself is NOT decoded — read it from the binary at the
    symbol's address once the length is known.
    """
    match = _string_const_regex.match(symbol)
    if match is None:
        return None
    try:
        strlen = (
            parse_encoded_number(match.group("len"))
            if "@" in match.group("len")
            else int(match.group("len"))
        )
    except (ValueError, InvalidEncodedNumberError):
        return None
    return StringConstInfo(length=strlen, is_utf16=match.group("is_utf16") == "1")


def msvc_demangle(symbol: str) -> str:
    """Demangle an MSVC symbol to a readable name ("" when impossible).

    Uses ``pydemumble`` when installed; the fallback strips the
    decoration tail (``@@``-terminated qualifier chain + ``@N`` byte
    count), which is enough for plain-C and __cdecl symbols.
    """
    try:
        from pydemumble import demangle as _demangle  # type: ignore[import-untyped]
    except ImportError:
        _demangle = None
    if _demangle is not None:
        return _demangle(symbol) or ""
    if not symbol.startswith("?"):
        return symbol  # not mangled
    name = symbol.lstrip("?").split("@")[0]
    return re.sub(r"@(?:(\d+))?$", "", name)


def get_function_arg_string(symbol: str) -> str | None:
    """The parenthesized parameter string of a demangled function symbol."""
    raw = msvc_demangle(symbol)
    if not raw:
        return None
    try:
        return raw[raw.index("(") : raw.rindex(")") + 1]
    except ValueError:
        return None


def demangle_vtable(symbol: str) -> str:
    """The class name referenced by a ``??_7`` vtable symbol.

    Self-contained parser (no demangler dependency): handles the simple
    and template-class cases; backrefs and virtual inheritance are not
    supported (ponytail: same ceiling as reccmp's parked implementation).
    """
    if not symbol.startswith("??_7"):
        return msvc_demangle(symbol)
    parts = symbol[4:].split("@")
    head = parts[0]
    if head.startswith("?$"):  # template class: ?$name@ARGS
        class_name = head[2:]
        # "PA" = pointer, "V"/"U" = class/struct, "X" = void
        arg = parts[1] if len(parts) > 1 else ""
        kind = arg[:2] if arg.startswith(("PA", "PB")) else arg[:1]
        template = {"V": "class", "U": "struct"}.get(kind, "")
        arg_name = arg.lstrip("PABUVX")
        if template:
            return f"{class_name}<class {arg_name}>"
        return class_name
    return head
