"""Lossless decoding of the Delphi 1 TPF0 form-stream subset observed in NE images.

Unknown value types are reported explicitly. Forms retain property order and
wire types; successful decoding does not establish recovery of event bodies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, override
lazy import struct
lazy from collections.abc import Iterator

from rebrew.errors import RebrewError
lazy from rebrew.formats.ne_loader import segment_file_ranges

_TYPE_INT8, _TYPE_INT16, _TYPE_INT32 = 0x02, 0x03, 0x04
_TYPE_STR, _TYPE_IDENT, _TYPE_FALSE, _TYPE_TRUE = 0x06, 0x07, 0x08, 0x09
_TYPE_BINARY, _TYPE_SET = 0x0A, 0x0B
_INDENT = "  "


class DfmError(RebrewError, ValueError):
    """The byte stream is not a form this decoder understands."""


@dataclass
class Component:
    cls: str
    name: str
    props: list[tuple[str, Value]] = field(default_factory=list)
    kids: list[Component] = field(default_factory=list)

    def walk(self) -> Iterator[Component]:
        yield self
        for kid in self.kids:
            yield from kid.walk()

    def events(self) -> list[tuple[str, str]]:
        """The `On...` handlers this component wires up, with their names."""
        return [
            (p, v.value) for p, v in self.props if p.startswith("On") and isinstance(v, Identifier)
        ]


def _short_string(text: str) -> bytes:
    try:
        raw = text.encode("latin1")
    except UnicodeEncodeError as exc:
        raise DfmError("Delphi 1 short strings must be Latin-1") from exc
    if len(raw) > 255:
        raise DfmError("Delphi 1 short strings cannot exceed 255 bytes")
    return bytes([len(raw)]) + raw


class Value:
    """A property value that remembers the type byte it was written with, so a
    decoded form encodes back to the exact bytes it came from."""

    type_byte: int = 0

    def encode(self) -> bytes:
        raise NotImplementedError


class Int8(Value):
    type_byte = _TYPE_INT8

    def __init__(self, value: int) -> None:
        self.value = value

    @override
    def encode(self) -> bytes:
        if not -128 <= self.value <= 127:
            raise DfmError("Int8 value is outside its signed byte range")
        return struct.pack("<b", self.value)


class Int16(Value):
    type_byte = _TYPE_INT16

    def __init__(self, value: int) -> None:
        self.value = value

    @override
    def encode(self) -> bytes:
        return struct.pack("<h", self.value)


class Int32(Value):
    type_byte = _TYPE_INT32

    def __init__(self, value: int) -> None:
        self.value = value

    @override
    def encode(self) -> bytes:
        return struct.pack("<i", self.value)


class Str(Value):
    type_byte = _TYPE_STR

    def __init__(self, value: str) -> None:
        self.value = value

    @override
    def encode(self) -> bytes:
        return _short_string(self.value)


class Identifier(Str):
    """An enum member or a sibling-component reference: written bare."""

    type_byte = _TYPE_IDENT


class Bool(Value):
    def __init__(self, value: bool, type_byte: int) -> None:
        self.value = value
        self.type_byte = type_byte

    @override
    def encode(self) -> bytes:
        return b""


class Binary(Value):
    """A `{ ... }` hex blob (icons, pictures)."""

    type_byte = _TYPE_BINARY

    def __init__(self, data: bytes) -> None:
        self.data = data

    @override
    def encode(self) -> bytes:
        return struct.pack("<I", len(self.data)) + self.data


class SetOfIdentifiers(Value):
    type_byte = _TYPE_SET

    def __init__(self, items: list[str]) -> None:
        self.items = items

    @override
    def encode(self) -> bytes:
        return b"".join(_short_string(item) for item in self.items) + b"\x00"


def encode(comp: Component) -> bytes:
    """A component and its children as the byte stream the linker appended."""
    out = bytearray(_short_string(comp.cls) + _short_string(comp.name))
    for name, value in comp.props:
        out += _short_string(name)
        out.append(value.type_byte)
        out += value.encode()
    out.append(0)
    for kid in comp.kids:
        out += encode(kid)
    out.append(0)
    return bytes(out)


def quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def render_value(value: Value, pad: str) -> str:
    """Delphi's text form: `Name = Value`, with enums and event handlers bare."""
    if isinstance(value, Identifier):
        return value.value
    if isinstance(value, Bool):
        return "True" if value.value else "False"
    if isinstance(value, SetOfIdentifiers):
        return "[" + ", ".join(value.items) + "]"
    if isinstance(value, Binary):
        body = "\n".join(
            pad + _INDENT + " ".join(f"{b:02X}" for b in value.data[i : i + 16])
            for i in range(0, len(value.data), 16)
        )
        return "{\n" + body + "\n" + pad + "}"
    if isinstance(value, Str):
        return quote(value.value)
    if isinstance(value, (Int8, Int16, Int32)):
        return str(value.value)
    raise DfmError(f"cannot render {value!r}")


def render(comp: Component, depth: int = 0) -> str:
    pad = _INDENT * depth
    lines = [f"{pad}object {comp.name}: {comp.cls}"]
    for prop, value in comp.props:
        lines.append(f"{pad}{_INDENT}{prop} = {render_value(value, pad + _INDENT)}")
    for kid in comp.kids:
        lines.append(render(kid, depth + 1))
    lines.append(f"{pad}end")
    return "\n".join(lines) + "\n"


False_ = Bool(False, _TYPE_FALSE)
True_ = Bool(True, _TYPE_TRUE)


class Reader:
    """A bounds-checked reader of Delphi 1 component/property streams."""

    def __init__(self, data: bytes, start: int) -> None:
        if not 0 <= start <= len(data):
            raise DfmError(f"form offset {start} is outside the input")
        self.data = data
        self.pos = start

    def _take(self, length: int) -> bytes:
        if length < 0 or self.pos + length > len(self.data):
            raise DfmError(f"truncated {length}-byte value at {self.pos}")
        result = self.data[self.pos : self.pos + length]
        self.pos += length
        return result

    def _peek(self) -> int:
        if self.pos >= len(self.data):
            raise DfmError(f"truncated component at {self.pos}")
        return self.data[self.pos]

    def short_string(self) -> str:
        length = self._take(1)[0]
        return self._take(length).decode("latin1")

    def value(self, type_byte: int) -> Value:
        """Read one supported property value without losing its wire type."""
        if type_byte == _TYPE_INT8:
            return Int8(struct.unpack("<b", self._take(1))[0])
        if type_byte == _TYPE_INT16:
            return Int16(struct.unpack("<h", self._take(2))[0])
        if type_byte == _TYPE_INT32:
            return Int32(struct.unpack("<i", self._take(4))[0])
        if type_byte == _TYPE_STR:
            return Str(self.short_string())
        if type_byte == _TYPE_IDENT:
            return Identifier(self.short_string())
        if type_byte == _TYPE_FALSE:
            return False_
        if type_byte == _TYPE_TRUE:
            return True_
        if type_byte == _TYPE_BINARY:
            size = struct.unpack("<I", self._take(4))[0]
            return Binary(self._take(size))
        if type_byte == _TYPE_SET:
            items = []
            while self._peek():
                items.append(self.short_string())
            self._take(1)
            return SetOfIdentifiers(items)
        raise DfmError(f"unsupported value type {type_byte:#04x} at {self.pos}")

    def component(self, depth: int = 0) -> Component:
        """Read a complete tree, refusing unterminated or excessively nested input."""
        if depth >= 128:
            raise DfmError("component nesting exceeds 128 levels")
        cls, name = self.short_string(), self.short_string()
        if not cls:
            raise DfmError(f"component has no class at {self.pos}")
        component = Component(cls, name)
        while self._peek():
            prop = self.short_string()
            component.props.append((prop, self.value(self._take(1)[0])))
        self._take(1)
        while self._peek():
            component.kids.append(self.component(depth + 1))
        self._take(1)
        return component


def parse_form(data: bytes, offset: int = 0) -> tuple[Component, int]:
    """Decode a TPF0 stream at offset, returning its root and exclusive end."""
    if offset < 0 or data[offset : offset + 4] != b"TPF0":
        raise DfmError(f"missing TPF0 signature at {offset}")
    reader = Reader(data, offset + 4)
    root = reader.component()
    return root, reader.pos


def form_offsets(data: bytes) -> list[int]:
    """TPF0 candidates outside NE segment bytes, or in a standalone stream/container."""
    ranges = segment_file_ranges(data) if data[:2] == b"MZ" else []
    offsets = []
    start = 0
    while (offset := data.find(b"TPF0", start)) >= 0:
        if not any(lo <= offset < hi for lo, hi in ranges):
            offsets.append(offset)
        start = offset + 4
    return offsets


def scan_forms(data: bytes) -> tuple[list[tuple[int, Component, int]], list[dict[str, Any]]]:
    """Validated form streams and explicit failures at remaining candidate markers.

    A TPF0 sequence inside a validated binary property is part of that property,
    not another form. Unsupported candidates remain visible instead of making
    a partial scan look complete.
    """
    forms = []
    errors = []
    end = 0
    for offset in form_offsets(data):
        if offset < end:
            continue
        try:
            root, end = parse_form(data, offset)
        except DfmError as exc:
            errors.append({"offset": offset, "error": str(exc)})
            continue
        forms.append((offset, root, end))
    return forms, errors


def parse_forms(data: bytes) -> list[tuple[int, Component, int]]:
    """Return validated forms, raising when candidate streams are unsupported or truncated."""
    forms, errors = scan_forms(data)
    if errors:
        raise DfmError(
            f"{len(errors)} form candidate(s) could not be decoded: {errors[0]['error']}"
        )
    return forms


def roundtrip(data: bytes) -> tuple[int, list[str]]:
    """Re-encode every decoded stream; unsupported input is never a passing round trip."""
    forms = parse_forms(data)
    failures = [root.cls for offset, root, end in forms if encode(root) != data[offset + 4 : end]]
    return len(forms), failures
