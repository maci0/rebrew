"""Materialized i386 COFF evidence and complete operand-selected literal audits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rebrew.coff_reloc import CoffRelocRecord
from rebrew.data_ownership import is_compiler_literal
from rebrew.formats.binary_model import BinaryInfo
from rebrew.formats.coff import load_coff


@dataclass(frozen=True)
class ObjectLiteral:
    """One actual relocation's literal definition, not a guessed pool address."""

    offset: int
    symbol: str
    relocation_type: int
    value: bytes
    error: str = ""


@dataclass(frozen=True)
class ObjectFunction:
    """Owned bytes and typed fixups for one complete selected native extent."""

    code: bytes
    relocs: tuple[CoffRelocRecord, ...]
    literals: tuple[ObjectLiteral, ...]
    local_symbols: dict[str, int]
    excluded_padding: int


def literal_size(name: str) -> int:
    """Decode a compiler-declared extent; never infer strings from the first NUL.

    String lengths follow LLVM's MicrosoftMangle.cpp mangleStringLiteral /
    mangleNumber (https://clang.llvm.org/doxygen/MicrosoftMangle_8cpp_source.html).
    Unrecognized encodings deliberately have no inferred extent.
    """
    if name.startswith("__real@"):
        parts = name[7:].split("@")
        if (
            len(parts) == 2
            and parts[0] in {"4", "8", "10", "16"}
            and parts[1]
            and all(c in "0123456789abcdefABCDEF" for c in parts[1])
        ):
            return int(parts[0])
        if (
            len(parts) == 1
            and len(parts[0]) in {8, 16, 20, 32}
            and all(c in "0123456789abcdefABCDEF" for c in parts[0])
        ):
            return len(parts[0]) // 2
    if name.startswith(("??_C@_0", "??_C@_1")):
        number = name[7:]
        if number and number[0].isdigit() and number[0].isascii():
            return int(number[0]) + 1
        digits, separator, _ = number.partition("@")
        if separator and digits and len(digits) <= 8 and all("A" <= c <= "P" for c in digits):
            return int("".join(f"{ord(c) - ord('A'):x}" for c in digits), 16)
    raise ValueError("unknown complete compiler-literal extent")


def object_function(raw: bytes, symbol: str, size: int) -> ObjectFunction:
    """Read a complete COFF function without trimming code or masking fixups."""
    if not symbol or size <= 0:
        raise ValueError("a native symbol and positive complete extent are required")
    loaded = load_coff(raw)
    if loaded is None:
        raise ValueError("not a supported COFF object")
    coff, symbols, names = loaded
    if int(coff.header.machine) != 0x14C:
        raise ValueError("object evidence currently requires i386 COFF")
    sections = list(coff.sections)
    # LIEF can return a partial parse after reporting truncated tables.
    if getattr(coff.header, "sizeof_optionalheader", 0) or len(sections) != coff.header.nb_sections:
        raise ValueError("object section table is incomplete or unsupported")
    records = sum(1 + len(s.auxiliary_symbols) for s in symbols)
    if (
        records != coff.header.nb_symbols
        or coff.header.pointerto_symbol_table + records * 18 + 4 > len(raw)
    ):
        raise ValueError("object symbol table is incomplete")
    for candidate in sections:
        if (
            candidate.offset + candidate.sizeof_raw_data > len(raw)
            or len(candidate.content) != candidate.sizeof_raw_data
        ):
            raise ValueError("object section bytes are incomplete")
        if candidate.has_extended_relocations:
            raise ValueError("extended COFF relocation tables are not supported by this audit")
        if (
            candidate.pointerto_relocation + candidate.numberof_relocations * 10 > len(raw)
            or len(candidate.relocations) != candidate.numberof_relocations
        ):
            raise ValueError("object relocation table is incomplete")
    matches = [
        s
        for s, n in zip(symbols, names, strict=True)
        if n == symbol and s.section_idx > 0 and s.is_function
    ]
    if len(matches) != 1:
        raise ValueError("select exactly one defined function symbol")
    function = matches[0]
    section_index, start = function.section_idx, function.value
    section = sections[section_index - 1]
    if not (int(section.characteristics) & 0x20 and int(section.characteristics) & 0x20000000):
        raise ValueError("object function must occupy an executable code section")
    boundary = min(
        (
            s.value
            for s in symbols
            if s.section_idx == section_index and s.is_function and s.value > start
        ),
        default=section.sizeof_raw_data,
    )
    end = start + size
    if end > boundary or start < 0 or section.offset + boundary > len(raw):
        raise ValueError("native extent exceeds the complete object function span")
    tail = bytes(section.content)[end:boundary]
    if len(tail) > 15 or any(byte not in {0x90, 0xCC} for byte in tail):
        raise ValueError("object function extends beyond the selected native extent")
    code = bytes(section.content)[start:end]
    if len(code) != size:
        raise ValueError("truncated object function bytes")
    indexed: dict[int, tuple[Any, str]] = {}
    index = 0
    for s, name in zip(symbols, names, strict=True):
        indexed[index] = (s, name)
        index += 1 + len(s.auxiliary_symbols)
    relocs: list[CoffRelocRecord] = []
    literals: list[ObjectLiteral] = []
    local_symbols = {
        name: s.value - start
        for s, name in zip(symbols, names, strict=True)
        if s.section_idx == section_index and start <= s.value < end
    }
    for name in local_symbols:
        if (
            len(
                {
                    s.value
                    for s, n in zip(symbols, names, strict=True)
                    if n == name and s.section_idx > 0
                }
            )
            != 1
        ):
            raise ValueError("ambiguous object-local symbol")
    for reloc in section.relocations:
        if reloc.address < start and reloc.address + 4 > start and int(reloc.type) & 0xFFFF:
            raise ValueError("relocation crosses the selected native start")
        if not start <= reloc.address < end:
            continue
        offset, kind = reloc.address - start, int(reloc.type) & 0xFFFF
        if offset + 4 > size and kind:
            raise ValueError("relocation crosses the selected native extent")
        target, name = indexed.get(reloc.symbol_idx, (None, ""))
        if target is None:
            raise ValueError("relocation has no valid symbol")
        relocs.append(CoffRelocRecord(offset, kind, name))
        if not is_compiler_literal(name) and not name.startswith("$SG"):
            continue
        error, value = "", b""
        try:
            if kind != 6:
                raise ValueError("literal reference requires IMAGE_REL_I386_DIR32")
            extent = literal_size(name)
            definitions = [
                s for s, n in zip(symbols, names, strict=True) if n == name and s.section_idx > 0
            ]
            if len(definitions) != 1:
                raise ValueError("literal definition is absent or ambiguous")
            definition = definitions[0]
            pool = sections[definition.section_idx - 1]
            a, b = definition.value, definition.value + extent
            if extent <= 0 or b > pool.sizeof_raw_data or pool.offset + b > len(raw):
                raise ValueError("literal extent is not completely file-backed in the object")
            if any(r.address < b and r.address + 4 > a for r in pool.relocations):
                raise ValueError("literal payload contains unresolved relocations")
            value = bytes(pool.content)[a:b]
            if len(value) != extent:
                raise ValueError("truncated literal payload")
        except ValueError as exc:
            error = str(exc)
        literals.append(ObjectLiteral(offset, name, kind, value, error))
    return ObjectFunction(code, tuple(relocs), tuple(literals), local_symbols, len(tail))


def native_span(info: BinaryInfo, va: int, size: int) -> bytes:
    """Read a complete file-backed native span, excluding BSS and truncated tails."""
    if size <= 0:
        raise ValueError("native span must have a positive extent")
    candidates = [
        s
        for s in info.sections.values()
        if s.va <= va and va + size <= s.va + min(s.size, s.raw_size)
    ]
    if len(candidates) != 1:
        raise ValueError("native span is not inside one file-backed section")
    section = candidates[0]
    offset = section.file_offset + va - section.va
    value = info.data[offset : offset + size]
    if offset < 0 or len(value) != size:
        raise ValueError("native span exceeds the actual file bytes")
    return value


def audit_literals(function: ObjectFunction, info: BinaryInfo, va: int) -> dict[str, Any]:
    """Compare complete values at addresses selected by native relocation operands."""
    if info.arch != "x86_32":
        raise ValueError("literal audit currently requires an x86_32 target")
    native = native_span(info, va, len(function.code))
    rows: list[dict[str, Any]] = []
    for literal in function.literals:
        row: dict[str, Any] = {
            "offset": literal.offset,
            "symbol": literal.symbol,
            "size": len(literal.value),
            "status": "unsupported",
            "reason": literal.error,
        }
        if not literal.error:
            offset = literal.offset
            addend = int.from_bytes(function.code[offset : offset + 4], "little")
            if addend >= len(literal.value):
                row.update(
                    status="unsupported", reason="literal addend is outside its complete extent"
                )
                rows.append(row)
                continue
            base = (int.from_bytes(native[offset : offset + 4], "little") - addend) & 0xFFFFFFFF
            row["native_va"] = base
            try:
                actual = native_span(info, base, len(literal.value))
                row.update(
                    status="equal" if actual == literal.value else "different",
                    reason="",
                    object_hex=literal.value.hex(),
                    native_hex=actual.hex(),
                )
            except ValueError as exc:
                row.update(status="unmapped", reason=str(exc))
        rows.append(row)
    return {
        "va": va,
        "size": len(function.code),
        "literals": rows,
        "complete": all(row["status"] == "equal" for row in rows),
        "excluded_object_padding": function.excluded_padding,
        "placement_verified": False,
        "ownership_verified": False,
    }
