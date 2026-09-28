"""import_table.py — Import-table parsing and import-stub detection.

Parses an import table via LIEF — a PE's DLL name → API name → IAT slot VA, or
an ELF's DT_NEEDED libraries and undefined dynamic symbols — and detects the
classic MSVC import stubs in ``.text``: ``jmp [iat]`` sequences (``FF 25``,
an absolute slot VA on PE32 and a RIP-relative displacement on PE32+).
Library layer under the ``rebrew imports`` command
(:mod:`rebrew.imports`) and every analysis pass that names imported APIs.
"""

from __future__ import annotations

import logging
import struct
import threading
from pathlib import Path
from typing import Any

from rebrew.pe_headers import PE32_PLUS_MAGIC, pe_layout

log = logging.getLogger(__name__)

#: Parsed import tables by file identity.  A run has one target, so a handful
#: of entries is all this ever holds; the bound only guards a long-lived
#: process walking many images.
_IMPORTS_CACHE_MAX = 8
_imports_cache: dict[str, list[dict[str, Any]]] = {}
_imports_lock = threading.Lock()


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

    Memoized per ``(resolved path, mtime_ns, size, ino)`` (bounded dict +
    lock, mirroring ``rebrew.binary_loader.iat_slot_vas``): one run parses the
    target from the report, pe_symbols, the binary gate, the decompiler
    dossier and the toolchain detector, and each miss re-ran a full LIEF parse
    of the same multi-megabyte image.  A rebuild at the same path invalidates
    via mtime/size/inode.  The caller gets fresh dicts, so a consumer that
    annotates a record cannot poison the cache.
    """
    key = _cache_key(binary_path)
    if key is not None:
        with _imports_lock:
            cached = _imports_cache.get(key)
            if cached is not None:
                _imports_cache[key] = _imports_cache.pop(key)
                return [dict(record) for record in cached]
    records = _parse_imports(binary_path)
    if key is not None and records is not None:
        with _imports_lock:
            _imports_cache[key] = [dict(record) for record in records]
            if len(_imports_cache) > _IMPORTS_CACHE_MAX:
                _imports_cache.pop(next(iter(_imports_cache)))
    return [] if records is None else records


def _cache_key(binary_path: Path) -> str | None:
    """Identity of *binary_path* for the import memo, or None if unstattable."""
    try:
        st = binary_path.stat()
    except OSError:
        return None
    return f"{binary_path.resolve()}:{st.st_mtime_ns}:{st.st_size}:{st.st_ino}"


def _parse_imports(binary_path: Path) -> list[dict[str, Any]] | None:
    """Uncached import-table parse; see :func:`parse_imports` for the shape.

    Returns ``None`` when the image could not be parsed at all, which is not
    the same answer as an image with no imports: the toolchain detector picks
    a different, confident-looking profile from a zero-import target.  A
    failure is never memoized, so a later call in the same run retries it.
    """
    from rebrew.binary_loader import is_ne, load_binary

    if is_ne(binary_path):
        try:
            info = load_binary(binary_path)
        except (OSError, KeyError, ValueError) as exc:
            log.warning("NE import parse failed for %s: %s", binary_path, exc)
            return None
        ne_out: list[dict[str, Any]] = []
        for mod in getattr(info, "ne_imports", []) or []:
            if mod.imports:
                for imp in mod.imports:
                    name = imp.name if imp.name is not None else f"ordinal_{imp.ordinal}"
                    ne_out.append(
                        {
                            "dll": mod.module,
                            "name": name,
                            "iat_va": 0,
                            "ordinal": imp.ordinal if imp.name is None else None,
                        }
                    )
            else:
                # Module reference with no per-API detail (many Win16 binaries
                # carry no classic import table) — still report the module so
                # the DLL set is visible.
                ne_out.append({"dll": mod.module, "name": "", "iat_va": 0, "ordinal": None})
        return ne_out

    import lief

    if lief.is_elf(str(binary_path)):
        try:
            elf = lief.ELF.parse(str(binary_path))
        except Exception as exc:  # LIEF raises on a malformed image
            log.warning("ELF import parse failed for %s: %s", binary_path, exc)
            return None
        if elf is None:
            log.warning("ELF import parse returned nothing for %s", binary_path)
            return None
        return elf_import_records(elf)

    try:
        pe = lief.PE.parse(str(binary_path))
    except Exception as exc:
        log.warning("PE import parse failed for %s: %s", binary_path, exc)
        return None
    if pe is None:
        log.warning("PE import parse returned nothing for %s", binary_path)
        return None
    opt = getattr(pe, "optional_header", None)
    if opt is None:
        log.warning("PE image base unavailable for %s", binary_path)
        return None
    try:
        imagebase = int(opt.imagebase)
    except (AttributeError, TypeError, ValueError) as exc:
        log.warning("PE image base unreadable for %s: %s", binary_path, exc)
        return None
    out: list[dict[str, Any]] = []
    try:
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
                        "dll": str(entry.name or ""),
                        "name": str(fn.name) if fn.name else f"ordinal_{ordinal}",
                        "iat_va": int(fn.iat_address) + imagebase,
                        "ordinal": ordinal or None,
                    }
                )
    except Exception as exc:
        # Mid-table: the records collected so far are real, but the IAT is
        # truncated.  Callers read this as a complete table, so name the
        # shortfall instead of returning a silently partial answer.
        log.warning(
            "PE import enumeration of %s failed after %d record(s): %s: %s",
            binary_path,
            len(out),
            type(exc).__name__,
            exc,
        )
        return out
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
    out: list[dict[str, Any]] = [
        {"dll": library, "name": "", "iat_va": 0, "ordinal": None} for library in libraries
    ]
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
                "ordinal": None,
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
        except Exception:  # noqa: S112  # a malformed version table must not cost the import list
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
    """Detect ``jmp [iat]`` import stubs in ``.text``.

    Returns ``{stub_va: api_name}`` for every ``FF 25`` sequence whose target
    resolves to an import-table slot.  These stubs are what the linker
    generates for each imported API, so the VA maps 1:1 to a function.

    The operand is 32 bits either way but means different things: a PE32 stub
    carries the slot's absolute VA (``jmp dword ptr [iat_va]``), a PE32+ stub a
    RIP-relative displacement (``jmp qword ptr [rip + disp32]``, resolved from
    the address of the following instruction).  A PE32+ read as absolute finds
    nothing, which is how x64 images silently reported zero stubs.
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
    if text is None or text.file_offset < 0 or text.size <= 0:
        return {}
    layout = pe_layout(info.data)
    rip_relative = layout is not None and layout.magic == PE32_PLUS_MAGIC
    stub_va = text.va
    blob = info.data[text.file_offset : text.file_offset + text.size]
    stubs: dict[int, str] = {}
    for i in range(len(blob) - 5):
        if blob[i] != 0xFF or blob[i + 1] != 0x25:
            continue
        operand = struct.unpack("<i", blob[i + 2 : i + 6])[0]
        target = (stub_va + i + 6 + operand) & 0xFFFFFFFFFFFFFFFF if rip_relative else operand
        name = table.get(target)
        if name is not None:
            stubs[stub_va + i] = name
    return stubs
