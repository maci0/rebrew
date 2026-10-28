"""Recover private data placement from selected COFF objects and the raw link.

A map-selected section must match the object's fixed bytes before its applied
DIR32 operands can locate private data. No reference addresses enter that step.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
lazy import json
lazy from collections import defaultdict
lazy from collections.abc import Callable
lazy from pathlib import Path, PureWindowsPath

lazy from rebrew.formats.coff import load_coff

if TYPE_CHECKING:
    from rebrew.config import ProjectConfig
    from rebrew.data_ownership import LinkSymbol


def coff_data_symbols(
    body: bytes, anchors: dict[str, int], read: Callable[[int, int], bytes]
) -> dict[str, int]:
    """Project local COFF definitions using map anchors and linked operands.

    Unsupported fixups, changed fixed bytes, conflicting bases, and sections
    without an independent map anchor supply no evidence. Static names remain
    scoped to this one object; the caller rejects collisions between objects.
    """
    parsed = load_coff(body)
    if parsed is None:
        return {}
    obj, symbols, names = parsed
    if obj.header.machine.name != "I386":
        return {}
    sections = list(obj.sections)
    bases: dict[int, set[int]] = defaultdict(set)
    for symbol, name in zip(symbols, names, strict=True):
        if symbol.section_idx > 0 and name in anchors:
            bases[symbol.section_idx].add(anchors[name] - symbol.value)
    inferred: dict[int, set[int]] = defaultdict(set)
    for index, section in enumerate(sections, 1):
        if len(bases[index]) != 1:
            continue
        base = next(iter(bases[index]))
        raw = bytes(section.content)
        relocs = list(section.relocations)
        if not raw or any(
            r.type.name not in {"I386_DIR32", "I386_REL32"}
            or r.address < 0
            or r.address + 4 > len(raw)
            for r in relocs
        ):
            continue
        native = read(base, len(raw))
        masked = {i for r in relocs for i in range(r.address, r.address + 4)}
        if (
            len(native) != len(raw)
            or len(masked) == len(raw)
            or any(
                a != b for i, (a, b) in enumerate(zip(raw, native, strict=True)) if i not in masked
            )
        ):
            continue
        candidates: dict[int, set[int]] = defaultdict(set)
        valid = True
        for reloc in relocs:
            reloc_symbol = reloc.symbol
            if reloc_symbol is None:
                valid = False
                break
            offset = reloc.address
            addend = int.from_bytes(raw[offset : offset + 4], "little")
            applied = int.from_bytes(native[offset : offset + 4], "little")
            if reloc_symbol.name in anchors:
                expected = anchors[reloc_symbol.name] + addend
                if reloc.type.name == "I386_REL32":
                    expected -= base + offset + 4
                if applied != expected & 0xFFFFFFFF:
                    valid = False
                    break
            if reloc.type.name != "I386_DIR32" or reloc_symbol.section_idx <= 0:
                continue
            target = sections[reloc_symbol.section_idx - 1]
            if target.name in {".data", ".rdata", ".bss"}:
                target_base = applied - addend - reloc_symbol.value
                if 0 <= target_base <= 0xFFFFFFFF:
                    candidates[reloc_symbol.section_idx].add(target_base)
        if valid:
            for section_index, values in candidates.items():
                inferred[section_index].update(values)
    result = {}
    for symbol, name in zip(symbols, names, strict=True):
        if symbol.section_idx <= 0 or symbol.section_idx > len(sections):
            continue
        section = sections[symbol.section_idx - 1]
        values = bases[symbol.section_idx] | inferred[symbol.section_idx]
        if (
            section.name in {".data", ".rdata", ".bss"}
            and len(values) == 1
            and name != section.name
            and 0 <= symbol.value < section.size
        ):
            result[name] = next(iter(values)) + symbol.value
    return result


def private_data_symbols(cfg: ProjectConfig, built: Path, map_path: Path) -> dict[str, int]:
    """Read selected project objects and cached archives, without compiling."""
    from rebrew.data_ownership import cached_data_archives, parse_link_map
    from rebrew.formats.archives import parse_archive
    from rebrew.formats.binary_loader import load_binary

    image = load_binary(built)
    if image.format != "pe":
        return {}
    rows = parse_link_map(map_path.read_text(encoding="utf-8", errors="replace"))
    by_object: dict[str, list[LinkSymbol]] = defaultdict(list)
    by_library_member: dict[str, dict[str, list[LinkSymbol]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in rows:
        by_object[PureWindowsPath(row.object or row.member).name].append(row)
        by_library_member[PureWindowsPath(row.library).stem.casefold()][
            row.member.casefold()
        ].append(row)

    def read(va: int, size: int) -> bytes:
        for section in image.sections.values():
            offset = va - section.va
            if offset >= 0 and offset + size <= section.raw_size:
                begin = section.file_offset + offset
                return bytes(image.data[begin : begin + size])
        return b""

    values: dict[str, set[int]] = defaultdict(set)

    def add(body: bytes, selected: list[LinkSymbol]) -> None:
        anchors: dict[str, set[int]] = defaultdict(set)
        for row in selected:
            anchors[row.name].add(row.va)
        unique = {name: next(iter(v)) for name, v in anchors.items() if len(v) == 1}
        for name, va in coff_data_symbols(body, unique, read).items():
            values[name].add(va)

    commands = map_path.parent / "compile_commands.json"
    if commands.is_file():
        for command in json.loads(commands.read_text()):
            output = command.get("output")
            if not output:
                continue
            obj = Path(output)
            if not obj.is_absolute():
                obj = Path(command["directory"]) / obj
            selected = by_object.get(obj.name, [])
            if selected and obj.is_file():
                add(obj.read_bytes(), selected)
    for library, archive in cached_data_archives(cfg).items():
        members = by_library_member.get(library, {})
        for member, body in parse_archive(str(archive)):
            name = PureWindowsPath(member).name.casefold()
            if name in members:
                add(body, members[name])
    return {name: next(iter(v)) for name, v in values.items() if len(v) == 1}


def span_data_placements(cfg: ProjectConfig, built: Path) -> dict[tuple[str, int], int]:
    """Locate inventory intervals by section-relative coordinates, not owners.

    A span is an interval in a section, not a C allocation. Both images must
    contain its complete interval. Its bytes still have to pass verification.
    """
    from rebrew.data_layout import data_symbol_size
    from rebrew.formats.binary_loader import load_binary
    from rebrew.metadata.data import load_data_metadata, module_visible_to_target

    reference, image = load_binary(cfg.target_binary), load_binary(built)
    aliases = {".bss": ".data", ".idata": ".rdata"}
    result = {}
    for (module, va), fields in load_data_metadata(cfg.metadata_dir).items():
        if fields.get("storage_kind") != "span" or not module_visible_to_target(module, cfg):
            continue
        name = str(fields.get("section") or "")
        if reference.format == image.format == "pe":
            name = aliases.get(name, name)
        native, linked = reference.sections.get(name), image.sections.get(name)
        size = data_symbol_size(fields, arch=getattr(cfg, "arch", "x86_32"))
        if native is None or linked is None or size <= 0:
            continue
        offset = va - native.va
        if offset >= 0 and offset + size <= min(native.size, linked.size):
            result[module, va] = linked.va + offset
    return result
