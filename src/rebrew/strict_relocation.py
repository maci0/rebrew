"""Strict PE/COFF relocation evidence from retained binary and object bytes.

The caller must authenticate that the object was produced from the captured
source by the current compiler generation before publishing this evidence.
"""

from __future__ import annotations

import hashlib
from typing import Any
lazy from pathlib import Path

import lief

from rebrew.coff_reloc import resolve_exact_then_stripped, smart_reloc_compare
from rebrew.errors import RebrewError
from rebrew.matcher.parsers import parse_obj_symbol_and_relocs


class StrictRelocationError(RebrewError, ValueError):
    """The binary or compiler output cannot prove a strict relocation match."""


def _aliases(name: str | bytes) -> set[str]:
    text = name if isinstance(name, str) else name.decode("utf-8", "replace")
    stripped = text.lstrip("_")
    return {text, stripped} - {""}


def strict_pe_relocation(
    binary: bytes,
    binary_sha256: str,
    object_path: Path,
    object_sha256: str,
    symbol: str,
    va: int,
    size: int,
) -> dict[str, Any]:
    """Prove an i386 COFF function's relocations against the same retained PE.

    Symbol and import identities come solely from the PE, never source metadata.
    Imported symbols are refused until their binding policy has its own proof.
    """
    if (
        type(binary) is not bytes
        or not binary
        or len(binary) > 512 * 1024 * 1024
        or hashlib.sha256(binary).hexdigest() != binary_sha256
    ):
        raise StrictRelocationError("binary digest mismatch")
    if (
        not symbol
        or type(va) is not int
        or va < 0
        or type(size) is not int
        or size <= 0
        or va + size > (1 << 32)
    ):
        raise StrictRelocationError("invalid target identity")
    if object_path.is_symlink() or not object_path.is_file():
        raise StrictRelocationError("invalid compiler object")
    if not 0 < object_path.stat().st_size <= 32 * 1024 * 1024:
        raise StrictRelocationError("invalid compiler object size")
    raw_object = object_path.read_bytes()
    if not raw_object or len(raw_object) > 32 * 1024 * 1024:
        raise StrictRelocationError("invalid compiler object size")
    if hashlib.sha256(raw_object).hexdigest() != object_sha256:
        raise StrictRelocationError("compiler object digest mismatch")
    try:
        image = lief.PE.parse(binary)
        if (
            image is None
            or image.header.machine != lief.PE.Header.MACHINE_TYPES.I386
            or image.optional_header.magic != lief.PE.PE_TYPE.PE32
        ):
            raise StrictRelocationError("strict relocation requires an i386 PE32")
        base = image.optional_header.imagebase
        sections = list(image.sections)
        function_sections = [
            s
            for s in sections
            if s.characteristics & 0x20000000
            and base + s.virtual_address <= va
            and va + size <= base + s.virtual_address + s.virtual_size
        ]
        if len(function_sections) != 1:
            raise StrictRelocationError("function extent is not in one executable section")
        section = function_sections[0]
        delta = va - base - section.virtual_address
        if (
            delta + size > section.sizeof_raw_data
            or section.pointerto_raw_data + delta + size > len(binary)
        ):
            raise StrictRelocationError("function bytes are not fully backed by the binary")
        target = bytes(image.get_content_from_virtual_address(va, size))
        if len(target) != size:
            raise StrictRelocationError("function bytes are unavailable")
        aliases: dict[str, set[int]] = {}
        for item in image.symbols:
            index = item.section_idx
            if not item.name or index <= 0 or index > len(sections):
                continue
            section = sections[index - 1]
            if (
                item.value < 0
                or item.value >= section.virtual_size
                or not section.characteristics & 0xE0000000
                or section.characteristics & 0x02000000
            ):
                continue
            address = base + section.virtual_address + item.value
            owners = [
                s
                for s in sections
                if s.characteristics & 0xE0000000
                and base + s.virtual_address <= address < base + s.virtual_address + s.virtual_size
            ]
            if len(owners) != 1:
                continue
            for alias in _aliases(item.name):
                aliases.setdefault(alias, set()).add(address)
        imported = {
            alias
            for library in image.imports
            for entry in library.entries
            if not entry.is_ordinal and entry.name
            for alias in _aliases(entry.name)
        }
        addresses = {
            name: next(iter(values)) for name, values in aliases.items() if len(values) == 1
        }
        if len(aliases.get(symbol, set())) != 1 or addresses.get(symbol) != va:
            raise StrictRelocationError("function symbol does not bind uniquely to the target")
        candidate, _compat, records = parse_obj_symbol_and_relocs(object_path, symbol)
        if candidate is None or len(candidate) != size or not records:
            raise StrictRelocationError("compiler object lacks a matching relocated function")
        offsets: set[int] = set()
        bindings: list[dict[str, Any]] = []
        for record in records:
            if (
                record.format != "coff-i386"
                or record.type not in (6, 20)
                or record.offset < 0
                or record.offset + 4 > size
                or any(pos in offsets for pos in range(record.offset, record.offset + 4))
            ):
                raise StrictRelocationError("unsupported or overlapping relocation")
            offsets.update(range(record.offset, record.offset + 4))
            names = _aliases(record.symbol)
            if names & imported or record.symbol.lstrip("_").startswith("imp_"):
                raise StrictRelocationError("import relocation proof is unavailable")
            if any(len(aliases.get(name, set())) > 1 for name in names):
                raise StrictRelocationError("ambiguous relocation symbol")
            resolved = resolve_exact_then_stripped(addresses, record.symbol)
            if resolved is None:
                raise StrictRelocationError("relocation symbol is absent from the binary")
            bindings.append(
                {
                    "offset": record.offset,
                    "type": record.type,
                    "symbol": record.symbol,
                    "address": resolved,
                }
            )
        matched, _count, _total, valid, invalid = smart_reloc_compare(
            candidate,
            target,
            records,
            name_to_va=addresses,
            section_va=va,
            strict=True,
            check_known_bindings=True,
        )
        if not matched or invalid or len(valid) != len(records):
            raise StrictRelocationError("relocation bytes do not match the binary bindings")
        if object_path.read_bytes() != raw_object:
            raise StrictRelocationError("compiler object changed during verification")
    except StrictRelocationError:
        raise
    except Exception as exc:
        raise StrictRelocationError("cannot verify PE relocation evidence") from exc
    return {
        "policy": "pe-coff-strict-v1",
        "binary_sha256": binary_sha256,
        "object_sha256": object_sha256,
        "symbol": symbol,
        "va": va,
        "size": size,
        "bindings": bindings,
    }
