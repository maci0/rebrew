"""import_table.py — Import-table parsing and import-stub detection.

Parses an import table via LIEF — a PE's DLL name → API name → IAT slot VA, or
an ELF's DT_NEEDED libraries and undefined dynamic symbols — and detects the
classic MSVC import stubs in ``.text``: ``jmp dword ptr [iat]`` sequences
(``FF 25 <va>``).  Library layer under the ``rebrew imports`` command
(:mod:`rebrew.imports`) and every analysis pass that names imported APIs.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any


def parse_imports(binary_path: Path) -> list[dict[str, Any]]:
    """Parse the import table of *binary_path* — the PE import table or the
    ELF dynamic imports via LIEF, or the 16-bit NE module/name imports via the
    native NE loader.

    Returns a list of ``{"dll": str, "name": str, "iat_va": int, "ordinal":
    int | None}`` records, one per imported API (``name`` is
    ``ordinal_<N>`` and ``ordinal`` is N for a PE import by ordinal), or one
    per referenced module with an empty ``name`` when a 16-bit NE carries no
    classic import table, or for an ELF's DT_NEEDED library entries, which
    precede its symbols.  ``iat_va`` is 0 for NE imports (Win16 uses
    per-segment thunks, not an IAT).  Empty list for unrecognized files or
    parse failures.
    """
    from rebrew.binary_loader import is_ne, load_binary

    if is_ne(binary_path):
        try:
            info = load_binary(binary_path)
        except (OSError, KeyError, ValueError):
            return []
        ne_out: list[dict[str, Any]] = []
        for mod in getattr(info, "ne_imports", []) or []:
            if mod.imports:
                for imp in mod.imports:
                    name = imp.name if imp.name is not None else f"ordinal_{imp.ordinal}"
                    ne_out.append({"dll": mod.module, "name": name, "iat_va": 0})
            else:
                # Module reference with no per-API detail (many Win16 binaries
                # carry no classic import table) — still report the module so
                # the DLL set is visible.
                ne_out.append({"dll": mod.module, "name": "", "iat_va": 0})
        return ne_out

    import lief

    if lief.is_elf(str(binary_path)):
        try:
            elf = lief.ELF.parse(str(binary_path))
        except Exception:  # best-effort symbol recovery: LIEF raises on a malformed image
            return []
        return [] if elf is None else elf_import_records(elf)

    try:
        pe = lief.PE.parse(str(binary_path))
    except Exception:  # best-effort symbol recovery
        return []
    if pe is None:
        return []
    imagebase = int(pe.optional_header.imagebase)
    out: list[dict[str, Any]] = []
    for entry in pe.imports:
        for fn in entry.entries:
            # An ordinal-only import (MFC's DLLs import by ordinal almost
            # exclusively) has no name in the hint/name table; naming it
            # ``ordinal_<N>`` keeps the IAT slot visible instead of dropping
            # it, and ``ordinal`` lets callers re-derive the linker's
            # ``__imp_<dll>_ord<N>`` spelling.  0 means a named import.
            ordinal = int(getattr(fn, "ordinal", 0) or 0)
            out.append(
                {
                    "dll": str(entry.name),
                    "name": str(fn.name) if fn.name else f"ordinal_{ordinal}",
                    "iat_va": int(fn.iat_address) + imagebase,
                    "ordinal": ordinal or None,
                }
            )
    return out


def elf_import_records(elf: Any) -> list[dict[str, Any]]:
    """Build the import records of a parsed LIEF ELF binary.

    One record per DT_NEEDED library in declaration order (``name`` empty, the
    module reference), then one per undefined dynamic symbol.  A symbol's
    ``dll`` is the library whose version requirement covers the version the
    symbol asks for; an image that declares none for a symbol leaves it
    unattributed rather than guessing, because DT_NEEDED names the libraries
    but never says which of them exports which symbol.
    """
    import lief

    libraries = [
        str(entry.name)
        for entry in elf.dynamic_entries
        if entry.tag == lief.ELF.DynamicEntry.TAG.NEEDED
    ]
    out: list[dict[str, Any]] = [{"dll": library, "name": "", "iat_va": 0} for library in libraries]
    slots = _elf_import_slots(elf)
    versions = _elf_version_libraries(elf)
    for symbol in elf.imported_symbols:
        name = str(symbol.name or "")
        if not name:
            continue
        out.append(
            {
                "dll": versions.get(_elf_symbol_version(symbol), ""),
                "name": name,
                "iat_va": slots.get(name, 0),
            }
        )
    return out


def _elf_symbol_version(symbol: Any) -> str:
    """The version name an ELF symbol requires, or ``""`` when it requires none."""
    version = getattr(symbol, "symbol_version", None)
    if version is None or not getattr(version, "has_auxiliary_version", False):
        return ""
    auxiliary = getattr(version, "symbol_version_auxiliary", None)
    return str(getattr(auxiliary, "name", "") or "")


def _elf_version_libraries(elf: Any) -> dict[str, str]:
    """Map every declared version name to the library that declares it.

    ``.gnu.version_r`` groups its version names by library, the only place an
    image states which library a versioned symbol comes from.
    """
    out: dict[str, str] = {}
    for requirement in getattr(elf, "symbols_version_requirement", None) or []:
        library = str(getattr(requirement, "name", "") or "")
        try:
            version_names = [str(aux.name or "") for aux in requirement.get_auxiliary_symbols()]
        except Exception:  # a malformed version table must not cost the whole import list
            continue
        for version_name in version_names:
            if version_name:
                out.setdefault(version_name, library)
    return out


def _elf_import_slots(elf: Any) -> dict[str, int]:
    """Map each imported symbol to the lowest address a relocation references it at.

    A dynamic image resolves an imported symbol through one GOT (or PLT) slot
    per reference; the lowest address is the slot an xref will reach, and the
    address is link-time, so a PIE's values are image-relative.
    """
    out: dict[str, int] = {}
    for relocation in getattr(elf, "relocations", None) or []:
        if not getattr(relocation, "has_symbol", False):
            continue
        name = str(relocation.symbol.name or "")
        if not name:
            continue
        address = int(relocation.address)
        if name not in out or address < out[name]:
            out[name] = address
    return out


def parse_import_table(binary_path: Path) -> dict[int, str]:
    """Return ``{iat_va: api_name}`` for *binary_path* (convenience view)."""
    return {rec["iat_va"]: rec["name"] for rec in parse_imports(binary_path)}


def find_import_stubs(binary_path: Path) -> dict[int, str]:
    """Detect ``jmp dword ptr [iat]`` import stubs in ``.text``.

    Returns ``{stub_va: api_name}`` for every ``FF 25 <iat_va>`` sequence
    whose target matches the import table.  These stubs are what the linker
    generates for each imported API, so the VA maps 1:1 to a function.
    """
    table = parse_import_table(binary_path)
    if not table:
        return {}
    from rebrew.binary_loader import load_binary

    try:
        info = load_binary(binary_path)
    except (OSError, KeyError, ValueError):
        return {}
    text = info.sections.get(".text")
    if text is None:
        return {}
    blob = info.data[text.file_offset : text.file_offset + text.size]
    stubs: dict[int, str] = {}
    for i in range(len(blob) - 5):
        if blob[i] != 0xFF or blob[i + 1] != 0x25:
            continue
        target = struct.unpack("<I", blob[i + 2 : i + 6])[0]
        name = table.get(target)
        if name is not None:
            stubs[text.va + i] = name
    return stubs
