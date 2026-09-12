"""pe_symbols.py: name a PE's data directories as symbol records.

A PE's loader metadata names addresses the disassembly alone cannot: the entry
point, the export table, every import-address-table slot, delay-load slots, TLS
callbacks, SafeSEH handlers, ``/guard:cf`` targets, and the load config's
security cookie.

Two public entry points:

- :func:`pe_directories` dumps those structures as typed records
  (:class:`PeImport`, :class:`PeExport`).  It is the shared reader: ``rebrew
  pe-info`` reports the same records it does.
- :func:`pe_symbols` turns them into named :class:`PeSymbol` records, which
  :mod:`rebrew.symbol_addrs` folds into its splat-style export.

Sources, in order of preference:

- LIEF through :func:`rebrew.binary_loader.load_binary` for the structures it
  parses (entry point, exports, TLS callbacks, the load config).
- :func:`rebrew.imports.parse_imports` for the import table, which already
  covers PE, ELF and 16-bit NE and names ordinal-only slots.
- The documented byte layout for three structures LIEF parses but does not
  enumerate.  The SafeSEH handler table and the ``/guard:cf`` target table are
  flat RVA arrays whose address and count come from LIEF; the delay-import
  directory is read from bytes because LIEF 0.17 misreads descriptors whose
  ``Attributes`` word is 0, where the PE spec says the fields are VAs rather
  than RVAs.  Each such reader is commented at its definition.

Every reader is guarded: a directory that is present but unreadable
contributes no record and appends a note to ``PeDirectories.notes`` instead of
raising, so one malformed structure never costs the whole symbol set.

Scope: rebrew builds 32-bit PE targets, so PE32+ ``.pdata`` unwind records
(``RUNTIME_FUNCTION`` / ``UNWIND_INFO``) and the CLR (``.NET``) header are out
of scope, as is the COFF symbol table.  A PE32+ image still parses; only its
unwind records are ignored.

Determinism: the same image yields the same records in the same order (sorted
by address, then name).  Nothing here reads the clock or the environment.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import lief

from rebrew.binary_loader import BinaryInfo, extract_bytes_at_va, load_binary
from rebrew.imports import parse_imports
from rebrew.pe_headers import pe_layout

# ---------------------------------------------------------------------------
# Named constants
# ---------------------------------------------------------------------------

#: ``PeSymbol.origin`` values, one per source directory.
ORIGIN_ENTRYPOINT = "entrypoint"
ORIGIN_EXPORT = "export"
ORIGIN_FORWARDER = "forwarder"
ORIGIN_IMPORT = "import"
ORIGIN_DELAY_IMPORT = "delay_import"
ORIGIN_TLS_CALLBACK = "tls_callback"
ORIGIN_SAFESEH = "safeseh"
ORIGIN_CFG_TARGET = "cfg_target"
ORIGIN_SECURITY_COOKIE = "security_cookie"

#: ``PeSymbol.kind`` values, named the way splat's ``symbol_addrs`` types are.
KIND_FUNC = "func"
KIND_U32 = "u32"
KIND_FORWARDER = "forwarder"

#: Bytes of one IAT slot (a 32-bit image's pointer).
_SLOT_SIZE = 4

#: ``IMAGE_DELAYLOAD_DESCRIPTOR`` is eight dwords; ``dlattrRva`` (bit 0) in the
#: ``Attributes`` word says whether its fields are RVAs or VAs.
_DELAY_DESCRIPTOR_SIZE = 32
_DELAY_ATTR_RVA = 0x1

#: Cap on table entries read from one directory.  The ``/guard:cf`` table of a
#: large system binary reaches tens of thousands of entries; a corrupt count
#: would otherwise turn one bad dword into an unbounded read.
_MAX_TABLE_ENTRIES = 65536

#: ``/guard:cf`` table entry encoding: an entry with its high bit set is
#: followed by one extra byte holding the entry's remaining flag bits.
_GUARD_TABLE_EXTRA_BIT = 0x80000000

#: High bit of an import name-table entry: the value is an ordinal, not an RVA.
_IMPORT_ORDINAL_FLAG = 0x80000000
_IMPORT_NAME_MASK = 0x7FFFFFFF

#: Cap on a hint/name or DLL-name string read.  The hint/name length byte is a
#: WORD, but a real entry is far shorter; the cap only bounds a corrupt one.
_MAX_NAME_BYTES = 512

#: Characters kept in a symbol name; anything else becomes ``_`` so the name is
#: a valid GAS/m2c label.
_LABEL_SAFE = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PeImport:
    """One imported slot.

    ``va`` is the absolute address of the slot (the IAT entry, or the
    delay-load IAT entry).  ``name`` is empty for an ordinal-only import, where
    ``ordinal`` carries the ordinal instead.
    """

    dll: str
    name: str
    ordinal: int | None
    va: int


@dataclass(frozen=True)
class PeExport:
    """One exported symbol.

    A forwarded export has no address in this image: ``va`` is ``None`` and
    ``forwarder`` names the ``DLL.Function`` it forwards to.
    """

    name: str
    ordinal: int | None
    va: int | None
    forwarder: str | None = None


@dataclass(frozen=True)
class PeDirectories:
    """Everything the PE data directories of one image state.

    ``notes`` is the module's note channel: a directory that is present but
    unreadable contributes no records and one note here, never an exception.
    """

    entrypoint: int | None = None
    exports: tuple[PeExport, ...] = ()
    imports: tuple[PeImport, ...] = ()
    delay_imports: tuple[PeImport, ...] = ()
    tls_callbacks: tuple[int, ...] = ()
    safe_seh_handlers: tuple[int, ...] = ()
    cfg_targets: tuple[int, ...] = ()
    security_cookie: int | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PeSymbol:
    """One symbol named from a PE data directory.

    ``va`` is absolute, or ``None`` for a forwarded export (which lives in
    another module; ``forwarder`` names its target).  ``kind`` is the splat
    symbol type.  ``size`` is the known byte size, or ``None`` when the
    structure does not state one.  ``detail`` is the short provenance note the
    ``symbol_addrs`` writer appends to the symbol's trailing comment.
    """

    va: int | None
    name: str
    kind: str
    origin: str
    size: int | None = None
    forwarder: str | None = None
    detail: str = ""


@dataclass(frozen=True)
class PeSymbolTable:
    """The symbols one image yields plus the notes explaining what was skipped."""

    symbols: tuple[PeSymbol, ...] = field(default_factory=tuple)
    notes: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Section math and pointer resolution
# ---------------------------------------------------------------------------


def _section_spans(layout: Any, image_base: int) -> list[tuple[int, int]]:
    """Absolute ``(start, end)`` for every section of a parsed PE layout."""
    spans: list[tuple[int, int]] = []
    for section in layout.sections:
        start = image_base + section.virtual_address
        size = max(section.virtual_size, section.size_of_raw_data)
        if size > 0:
            spans.append((start, start + size))
    return spans


def _inside(spans: list[tuple[int, int]], va: int) -> bool:
    """Whether *va* falls inside one of the section spans."""
    return any(start <= va < end for start, end in spans)


class _Image:
    """A parsed PE's section spans and image base, for pointer resolution.

    Wraps :func:`rebrew.pe_headers.pe_layout` so the RVA-vs-VA decision
    (:meth:`resolve`) and the byte reads share one section model.
    """

    def __init__(self, data: bytes, info: BinaryInfo, image_base: int) -> None:
        layout = pe_layout(data)
        self.image_base = image_base
        self.spans = _section_spans(layout, image_base) if layout is not None else []
        self._info = info

    def resolve(self, value: int | None) -> int | None:
        """Canonical absolute VA for a pointer stored in a PE structure.

        PE structures store RVAs, but linkers have shipped absolute VAs in
        these fields (Watcom's PE32+ load config, MSVC's VA-based delay-import
        descriptors).  The section table decides: the RVA reading wins when it
        lands inside a mapped section (the spec's meaning), otherwise the value
        is taken as already absolute when it lands inside one.  ``None`` when
        neither reading is mapped, so an unmapped pointer is never reported as
        a fabricated address.
        """
        if not value:
            return None
        rva_reading = self.image_base + value
        if _inside(self.spans, rva_reading):
            return rva_reading
        if _inside(self.spans, value):
            return value
        return None

    def read(self, va: int, size: int) -> bytes:
        """File bytes at *va*, empty when the address is unmapped."""
        if size <= 0:
            return b""
        return extract_bytes_at_va(self._info, va, size, trim_padding=False) or b""


# ---------------------------------------------------------------------------
# Byte-level directory readers
# ---------------------------------------------------------------------------


def _read_delay_imports(image: _Image, directory_rva: int) -> tuple[list[PeImport], list[str]]:
    """Delay-import slots from the delay-load directory at *directory_rva*.

    The descriptor's fields are RVAs when ``Attributes`` sets ``dlattrRva`` and
    VAs otherwise.  LIEF 0.17 reads them as RVAs unconditionally, so every
    MSVC ``__delayLoadHelper2`` descriptor (which leaves ``Attributes`` 0 and
    stores VAs) parses as garbage there.  Each slot's name table is the
    ordinary import name table, where a high-bit entry is an ordinal.
    """
    notes: list[str] = []
    records: list[PeImport] = []
    base_va = image.image_base + directory_rva
    index = 0
    while True:
        descriptor = image.read(base_va + index * _DELAY_DESCRIPTOR_SIZE, _DELAY_DESCRIPTOR_SIZE)
        if len(descriptor) < _DELAY_DESCRIPTOR_SIZE:
            break
        attributes = struct.unpack_from("<I", descriptor, 0x00)[0]
        name_field = struct.unpack_from("<I", descriptor, 0x04)[0]
        iat_field = struct.unpack_from("<I", descriptor, 0x0C)[0]
        int_field = struct.unpack_from("<I", descriptor, 0x10)[0]
        if not any((attributes, name_field, iat_field, int_field)):
            break
        rva_based = bool(attributes & _DELAY_ATTR_RVA)
        module = Path(_read_c_string(image, name_field, rva_based)).name
        iat_va = _resolve_field(image, iat_field, rva_based)
        int_va = _resolve_field(image, int_field, rva_based)
        if not module or iat_va is None or int_va is None:
            notes.append(
                f"delay-import descriptor {index} is unreadable "
                f"(dll={module or '?'}, iat={iat_field:#x}, names={int_field:#x})"
            )
        else:
            records.extend(_delay_slots(image, module, iat_va, int_va))
        index += 1
    return records, notes


def _delay_slots(image: _Image, module: str, iat_va: int, int_va: int) -> list[PeImport]:
    """One record per delay-import slot named by the *int_va* name table.

    The name table's entries follow the descriptor's own encoding, so each is
    resolved through the section table rather than assumed to be one form.
    """
    records: list[PeImport] = []
    for slot, entry in enumerate(_iter_name_table(image, int_va)):
        va = iat_va + slot * _SLOT_SIZE
        if not _inside(image.spans, va):
            break
        if entry & _IMPORT_ORDINAL_FLAG:
            records.append(PeImport(dll=module, name="", ordinal=entry & 0xFFFF, va=va))
            continue
        entry_va = image.resolve(entry & _IMPORT_NAME_MASK)
        name = _read_hint_name(image, entry_va) if entry_va is not None else ""
        if not name:
            break
        records.append(PeImport(dll=module, name=name, ordinal=None, va=va))
    return records


def _iter_name_table(image: _Image, table_va: int) -> Iterator[int]:
    """Yield the 32-bit entries of an import name table until its terminator."""
    for index in range(_MAX_TABLE_ENTRIES):
        raw = image.read(table_va + index * _SLOT_SIZE, _SLOT_SIZE)
        if len(raw) < _SLOT_SIZE:
            return
        entry = struct.unpack_from("<I", raw, 0)[0]
        if entry == 0:
            return
        yield entry


def _read_hint_name(image: _Image, entry_va: int) -> str:
    """The ASCII name of a hint/name table entry (a WORD hint then the name)."""
    raw = image.read(entry_va, _MAX_NAME_BYTES)
    if len(raw) < 3:
        return ""
    terminator = raw.find(b"\x00", 2)
    body = raw[2:] if terminator < 0 else raw[2:terminator]
    return body.decode("ascii", errors="replace")


def _read_c_string(image: _Image, field: int, rva_based: bool) -> str:
    """An ASCII string at a descriptor field, empty when unmapped."""
    va = _resolve_field(image, field, rva_based)
    if va is None:
        return ""
    return image.read(va, _MAX_NAME_BYTES).split(b"\x00")[0].decode("ascii", errors="replace")


def _resolve_field(image: _Image, field: int, rva_based: bool) -> int | None:
    """Resolve a descriptor field, honoring the descriptor's ``dlattrRva`` bit."""
    if not field:
        return None
    return image.image_base + field if rva_based else image.resolve(field)


def _read_safe_seh_entries(
    image: _Image, table: int | None, count: int | None
) -> tuple[list[int], list[str]]:
    """Handler VAs from the load config's SafeSEH table.

    The table address and entry count come from LIEF, which parses the load
    config but does not enumerate these entries (its ``seh_functions`` list
    came back empty for a synthetic PE whose table LIEF itself reported).
    Entries are 4-byte RVAs per the PE/COFF spec, so they are read from the
    image bytes; an entry whose target is not mapped is dropped rather than
    emitted as a fabricated address.
    """
    if not count:
        return [], []
    table_va = image.resolve(table)
    if table_va is None:
        return [], [f"SafeSEH handler table address ({_pointer_text(table)}) is not mapped"]
    entries = _read_rva_array(image, table_va, count, extra_byte=False)
    if len(entries) < count:
        return entries, [
            f"SafeSEH handler table at {table_va:#010x} is unreadable "
            f"({len(entries)} of {count} entries read)"
        ]
    return entries, []


def _read_cfg_targets(
    image: _Image, table: int | None, count: int | None
) -> tuple[list[int], list[str]]:
    """Target VAs from the load config's ``/guard:cf`` function table.

    Same source split as :func:`_read_safe_seh_entries`: the table address and
    count come from LIEF, the entries from the image bytes because LIEF's
    ``guard_cf_functions`` list does not enumerate them.  An entry with its
    high bit set is followed by one extra byte (MSVC's guard-table encoding),
    which the walk skips to stay aligned.
    """
    if not count:
        return [], []
    table_va = image.resolve(table)
    if table_va is None:
        return [], [f"/guard:cf target table address ({_pointer_text(table)}) is not mapped"]
    entries = _read_rva_array(image, table_va, count, extra_byte=True)
    if len(entries) < count:
        return entries, [
            f"/guard:cf target table at {table_va:#010x} is unreadable "
            f"({len(entries)} of {count} entries read)"
        ]
    return entries, []


def _pointer_text(value: int | None) -> str:
    """A pointer field for a note: its hex value, or ``none``."""
    return f"{value:#x}" if value else "none"


def _read_rva_array(image: _Image, table_va: int, count: int, *, extra_byte: bool) -> list[int]:
    """Read up to *count* RVA entries at *table_va*, keeping only mapped targets."""
    limit = min(count, _MAX_TABLE_ENTRIES)
    out: list[int] = []
    offset = 0
    for _ in range(limit):
        raw = image.read(table_va + offset, _SLOT_SIZE)
        if len(raw) < _SLOT_SIZE:
            break
        value = struct.unpack_from("<I", raw, 0)[0]
        offset += 5 if extra_byte and value & _GUARD_TABLE_EXTRA_BIT else _SLOT_SIZE
        va = image.image_base + (value & _IMPORT_NAME_MASK)
        if _inside(image.spans, va):
            out.append(va)
    return out


# ---------------------------------------------------------------------------
# LIEF-backed readers
# ---------------------------------------------------------------------------


def _read_exports(pe: Any, image_base: int) -> tuple[list[PeExport], list[str]]:
    """Export records, code and forwarded alike."""
    table = _export_table(pe)
    if table is None:
        return [], []
    exports: list[PeExport] = []
    for entry in _as_list(table, "entries"):
        original = str(getattr(entry, "name", "") or "")
        ordinal = _int_or_none(getattr(entry, "ordinal", None))
        name = original or (f"export_{ordinal}" if ordinal is not None else "")
        if not name:
            continue
        if bool(getattr(entry, "is_forwarded", False)):
            exports.append(
                PeExport(name=name, ordinal=ordinal, va=None, forwarder=_forwarder_target(entry))
            )
            continue
        address = _int_or_none(getattr(entry, "address", None))
        if address is None:
            continue
        exports.append(PeExport(name=name, ordinal=ordinal, va=image_base + address))
    return exports, []


def _export_table(pe: Any) -> Any | None:
    """The PE export table, or ``None`` when LIEF cannot expose one."""
    get_export = getattr(pe, "get_export", None)
    if get_export is None:
        return None
    try:
        return get_export()
    except (AttributeError, TypeError, ValueError, RuntimeError):
        return None


def _forwarder_target(entry: Any) -> str | None:
    """The ``DLL.Function`` an export forwards to, or ``None``."""
    info = getattr(entry, "forward_information", None)
    if info is None:
        return None
    library = getattr(info, "library", None)
    function = getattr(info, "function", None)
    if isinstance(library, str) and isinstance(function, str) and library and function:
        return f"{library}.{function}"
    return None


def _read_tls_callbacks(pe: Any) -> tuple[list[int], list[str]]:
    """Absolute VAs of the TLS callbacks, plus notes on unreadable ones.

    LIEF already resolves the callback array to absolute VAs.  The TLS
    *directory* being present is not enough: a linker may leave
    ``AddressOfCallbacks`` pointing outside the image, which yields no
    callbacks and one note.
    """
    tls = getattr(pe, "tls", None)
    if tls is None:
        return [], []
    callbacks = [_int_or_none(va) for va in _as_list(tls, "callbacks")]
    resolved = [va for va in callbacks if va is not None]
    if resolved:
        return resolved, []
    pointer = _int_or_none(getattr(tls, "addressof_callbacks", None))
    if pointer:
        return [], [f"TLS callback array at {pointer:#010x} yields no callbacks"]
    return [], []


def _read_imports(path: Path) -> list[PeImport]:
    """The image's import table as records (absolute slot VAs).

    ``parse_imports`` names an ordinal-only slot ``ordinal_<N>`` so the slot
    stays visible; that synthetic name is dropped here (the ordinal field
    already carries it) so every reader sees one shape.
    """
    records: list[PeImport] = []
    for record in parse_imports(path):
        va = int(record.get("iat_va") or 0)
        if not va:
            continue
        ordinal = _int_or_none(record.get("ordinal"))
        name = str(record.get("name", ""))
        if ordinal is not None and name == f"ordinal_{ordinal}":
            name = ""
        records.append(
            PeImport(
                dll=str(record.get("dll", "")),
                name=name,
                ordinal=ordinal,
                va=va,
            )
        )
    return records


def _read_load_config(image: _Image, pe: Any) -> tuple[list[int], list[int], int | None, list[str]]:
    """SafeSEH handlers, CFG targets, and the security cookie from the load config."""
    config = getattr(pe, "load_configuration", None)
    if config is None:
        return [], [], None, []
    handlers, handler_notes = _read_safe_seh_entries(
        image,
        _int_or_none(getattr(config, "se_handler_table", None)),
        _int_or_none(getattr(config, "se_handler_count", None)),
    )
    targets, target_notes = _read_cfg_targets(
        image,
        _int_or_none(getattr(config, "guard_cf_function_table", None)),
        _int_or_none(getattr(config, "guard_cf_function_count", None)),
    )
    cookie = image.resolve(_int_or_none(getattr(config, "security_cookie", None)))
    return handlers, targets, cookie, handler_notes + target_notes


# ---------------------------------------------------------------------------
# Public readers
# ---------------------------------------------------------------------------


def pe_directories(path: str | Path) -> PeDirectories:
    """The PE data directories of the image at *path*, as typed records.

    Never raises for a missing, non-PE, or malformed image: those return an
    empty ``PeDirectories`` whose notes say why.  This is the reader
    ``rebrew pe-info`` reports, and :func:`pe_symbols` names it.
    """
    target = Path(path)
    if not target.exists():
        return PeDirectories(notes=(f"binary not found: {target}",))
    try:
        is_pe = lief.is_pe(str(target))
    except (OSError, ValueError, RuntimeError) as exc:
        return PeDirectories(notes=(f"cannot identify {target.name}: {exc}",))
    if not is_pe:
        return PeDirectories(notes=(f"not a PE image: {target.name}",))
    try:
        pe = lief.PE.parse(str(target))
    except (OSError, ValueError, RuntimeError) as exc:
        return PeDirectories(notes=(f"cannot parse {target.name}: {exc}",))
    if pe is None:
        return PeDirectories(notes=(f"cannot parse {target.name}",))
    try:
        info = load_binary(target)
    except (OSError, ValueError, KeyError) as exc:
        return PeDirectories(notes=(f"cannot load {target.name}: {exc}",))

    image_base = _int_or_none(getattr(getattr(pe, "optional_header", None), "imagebase", 0)) or 0
    image = _Image(info.data, info, image_base)

    exports, export_notes = _read_exports(pe, image_base)
    callbacks, callback_notes = _read_tls_callbacks(pe)
    handlers, targets, cookie, config_notes = _read_load_config(image, pe)

    delay_records: list[PeImport] = []
    delay_notes: list[str] = []
    for directory in _as_list(pe, "data_directories"):
        if str(getattr(directory, "type", "")).endswith("DELAY_IMPORT_DESCRIPTOR"):
            rva = _int_or_none(getattr(directory, "rva", None))
            if rva:
                delay_records, delay_notes = _read_delay_imports(image, rva)
            break

    entry_rva = _int_or_none(
        getattr(getattr(pe, "optional_header", None), "addressof_entrypoint", None)
    )
    entrypoint = image_base + entry_rva if entry_rva else None

    notes = list(dict.fromkeys(export_notes + callback_notes + delay_notes + config_notes))
    return PeDirectories(
        entrypoint=entrypoint,
        exports=tuple(exports),
        imports=tuple(_read_imports(target)),
        delay_imports=tuple(delay_records),
        tls_callbacks=tuple(callbacks),
        safe_seh_handlers=tuple(handlers),
        cfg_targets=tuple(targets),
        security_cookie=cookie,
        notes=tuple(notes),
    )


# ---------------------------------------------------------------------------
# Symbol naming
# ---------------------------------------------------------------------------


def _sanitize_identifier(text: str) -> str:
    """*text* as a GAS/m2c-safe label.

    Characters outside ``[A-Za-z0-9_]`` become ``_`` and a leading digit gains
    a ``_`` prefix (a label may not start with one).  An empty result becomes
    ``sym`` so a name is never the empty string.
    """
    sanitized = "".join(char if char in _LABEL_SAFE else "_" for char in text)
    if sanitized and sanitized[0].isdigit():
        sanitized = "_" + sanitized
    return sanitized or "sym"


def iat_symbol_name(dll: str, name: str, ordinal: int | None) -> str:
    """Symbol name for one import IAT slot: ``__imp_<dll>_<name>``.

    The DLL token loses its directory, extension and case, matching how the
    MSVC linker writes ``__imp_`` symbols.  An ordinal-only import (MFC imports
    by ordinal almost exclusively) is named ``__imp_<dll>_ord<N>`` because it
    has no name to use.
    """
    token = Path(dll).name
    if "." in token:
        token = token.rsplit(".", 1)[0]
    token = _sanitize_identifier(token).lower()
    if ordinal is not None:
        return f"__imp_{token}_ord{ordinal}"
    if name:
        return f"__imp_{token}_{_sanitize_identifier(name)}"
    return f"__imp_{token}"


def delay_import_symbol_name(dll: str, name: str, ordinal: int | None) -> str:
    """Symbol name for one delay-load slot: ``__dimp_<dll>_<name>``.

    A distinct ``__dimp_`` prefix keeps a delay-load slot from colliding with a
    same-named static ``__imp_`` slot in a binary that uses both.
    """
    return "__dimp_" + iat_symbol_name(dll, name, ordinal).removeprefix("__imp_")


def pe_symbols(path: str | Path) -> PeSymbolTable:
    """Named symbols for the PE data directories of the image at *path*.

    Never raises for a missing, non-PE, or malformed image: those return an
    empty table whose notes say why.  The record set is deterministic (sorted
    by address, then name, then origin).
    """
    directories = pe_directories(path)
    symbols: list[PeSymbol] = []

    if directories.entrypoint is not None:
        symbols.append(
            PeSymbol(
                va=directories.entrypoint,
                name="entrypoint",
                kind=KIND_FUNC,
                origin=ORIGIN_ENTRYPOINT,
            )
        )
    for export in directories.exports:
        sanitized = _sanitize_identifier(export.name)
        if export.va is None:
            symbols.append(
                PeSymbol(
                    va=None,
                    name=sanitized,
                    kind=KIND_FORWARDER,
                    origin=ORIGIN_FORWARDER,
                    forwarder=export.forwarder,
                    detail=export.name if export.name != sanitized else "",
                )
            )
            continue
        symbols.append(
            PeSymbol(
                va=export.va,
                name=sanitized,
                kind=KIND_FUNC,
                origin=ORIGIN_EXPORT,
                detail=export.name if export.name != sanitized else "",
            )
        )
    for record in directories.imports:
        symbols.append(
            PeSymbol(
                va=record.va,
                name=iat_symbol_name(record.dll, record.name, record.ordinal),
                kind=KIND_U32,
                origin=ORIGIN_IMPORT,
                size=_SLOT_SIZE,
                detail=f"import from {record.dll}",
            )
        )
    for record in directories.delay_imports:
        symbols.append(
            PeSymbol(
                va=record.va,
                name=delay_import_symbol_name(record.dll, record.name, record.ordinal),
                kind=KIND_U32,
                origin=ORIGIN_DELAY_IMPORT,
                size=_SLOT_SIZE,
                detail=f"delay-loaded import from {record.dll}",
            )
        )
    for index, va in enumerate(directories.tls_callbacks):
        symbols.append(
            PeSymbol(
                va=va, name=f"tls_callback_{index}", kind=KIND_FUNC, origin=ORIGIN_TLS_CALLBACK
            )
        )
    for index, va in enumerate(directories.safe_seh_handlers):
        symbols.append(
            PeSymbol(va=va, name=f"safeseh_{index}", kind=KIND_FUNC, origin=ORIGIN_SAFESEH)
        )
    for index, va in enumerate(directories.cfg_targets):
        symbols.append(
            PeSymbol(va=va, name=f"cfg_target_{index}", kind=KIND_FUNC, origin=ORIGIN_CFG_TARGET)
        )
    if directories.security_cookie is not None:
        symbols.append(
            PeSymbol(
                va=directories.security_cookie,
                name="security_cookie",
                kind=KIND_U32,
                origin=ORIGIN_SECURITY_COOKIE,
                size=_SLOT_SIZE,
            )
        )

    symbols.sort(key=_symbol_sort_key)
    return PeSymbolTable(tuple(symbols), directories.notes)


def _symbol_sort_key(symbol: PeSymbol) -> tuple[int, int, str, str]:
    """Sort key: addressed symbols first by address, then forwarded exports."""
    if symbol.va is None:
        return (1, 0, symbol.name, symbol.origin)
    return (0, symbol.va, symbol.name, symbol.origin)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _as_list(obj: Any, attr: str) -> list[Any]:
    """``obj.attr`` as a list, or ``[]`` when missing or not iterable."""
    try:
        value = getattr(obj, attr, None)
    except (AttributeError, TypeError, ValueError, RuntimeError):
        return []
    if value is None:
        return []
    try:
        return list(value)
    except TypeError:
        return []


def _int_or_none(value: Any) -> int | None:
    """*value* as an int, or ``None`` when it is not integer-like."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
