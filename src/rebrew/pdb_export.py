"""rebrew export pdb: write a synthetic PDB for the original target binary.

The PDB carries what rebrew has recovered about the target, stamped with the
identity the target's CodeView debug record asks for, so a debugger or
disassembler pairs it with that exact build:

- **functions**: every annotated function as an ``S_PUB32`` public, plus an
  ``S_GPROC32`` procedure (with its byte size and a section contribution)
  when the annotation has a size;
- **data**: every annotated global and every named ``rebrew-data.toml`` row
  visible to the target, as ``S_PUB32`` + ``S_GDATA32``.  A data type that is
  a C scalar, a pointer to one, or an array of either becomes a CodeView type;
  structs, typedefs, and function pointers stay untyped;
- **PE symbols** (``--pe-symbols``): the entry point, exports, IAT slots, and
  the other names :mod:`rebrew.formats.pe_symbols` reads from the data directories;
- the target's own section headers, so tools map ``segment:offset`` back to
  addresses without the image.

Identity comes from the first CODEVIEW debug-directory entry:

- ``RSDS`` (PDB 7.0, VC7+ linkers): the GUID and age are copied.  Every tool
  that matches by GUID + age accepts the file as the build's symbols.
- ``NB10`` (PDB 2.0, VC6 and older linkers): the 32-bit signature and age are
  copied and the GUID is left zero.  ``llvm-pdbutil`` writes only the 7.0
  container, and a 7.0 file always carries a GUID: Ghidra matches a 7.0 file
  by GUID, so it reports a mismatch and the file must be force-loaded there.
- no CodeView record: nothing identifies a matching PDB, so the command
  refuses unless ``--unmatched`` is passed, which writes zero identifiers for
  tools that load a PDB on request.

The PDB is assembled by ``llvm-pdbutil yaml2pdb`` from a JSON document (JSON
is valid YAML) piped on stdin, then read back with ``llvm-pdbutil dump
-summary`` to confirm the identity landed.  No Python library writes MSF/PDB
files, so this is the one external process; a missing tool is a hard error.

Usage::

    rebrew export pdb
    rebrew export pdb --pe-symbols --output build/game.pdb
    rebrew export pdb --unmatched --output game.pdb   # target has no CodeView record
"""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any, Literal

import typer

from rebrew.cli import EXIT_ERROR, TargetOption, console, error_exit, json_print, require_config
from rebrew.errors import RebrewError
from rebrew.formats.pe_symbols import KIND_FUNC, pe_symbols
from rebrew.symbol_addrs import SymbolRow, function_symbol_rows, merge_pe_symbols
from rebrew.utils import untrusted_ident

app = typer.Typer(
    help="Write a synthetic PDB for the target binary from rebrew's symbols.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew export pdb · · · · · · · · · · · Functions + data, named as the target expects\n\n"
        "  rebrew export pdb --pe-symbols · · · · Also IAT slots, exports, TLS callbacks, ...\n\n"
        "  rebrew export pdb --unmatched -o x.pdb · Target has no CodeView record\n\n"
        "[dim]Needs llvm-pdbutil on PATH.  The PDB is stamped with the GUID/age\n"
        "(RSDS) or signature/age (NB10) from the target's debug directory.[/dim]"
    ),
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: CodeView record magics (the first four bytes of the debug record).
_RSDS = b"RSDS"
_NB10 = b"NB10"
#: NB10 layout: magic, offset, signature, age, then the PDB path.
_NB10_HEADER = struct.Struct("<4sIII")
_ZERO_GUID = "{00000000-0000-0000-0000-000000000000}"

#: Seconds llvm-pdbutil may take; a large target writes in well under one.
_PDBUTIL_TIMEOUT_S = 120

#: Module stream layout: a 4-byte CV signature, then 4-byte aligned records
#: of ``u16 length, u16 kind, payload``.  Fixed payload bytes before the
#: NUL-terminated name, per record kind.
_MODULE_STREAM_SIGNATURE = 4
_RECORD_HEADER = 4
_OBJNAME_FIXED = 4
_GPROC32_FIXED = 35
_GDATA32_FIXED = 10
_RECORD_ALIGN = 4
_OBJECT_NAME = "rebrew"

#: DBI build number lld writes: new-format bit | MSVC 14.11.
_DBI_BUILD_NUMBER = 0x8000 | (14 << 8) | 11

#: CodeView simple-type indices (cvinfo.h ``T_*``) for C base types.
_SIMPLE_TYPES: dict[str, int] = {
    "void": 0x0003,
    "char": 0x0070,
    "signed char": 0x0010,
    "unsigned char": 0x0020,
    "bool": 0x0030,
    "_Bool": 0x0030,
    "wchar_t": 0x0071,
    "short": 0x0011,
    "short int": 0x0011,
    "signed short": 0x0011,
    "signed short int": 0x0011,
    "unsigned short": 0x0021,
    "unsigned short int": 0x0021,
    "int": 0x0074,
    "signed": 0x0074,
    "signed int": 0x0074,
    "unsigned": 0x0075,
    "unsigned int": 0x0075,
    "long": 0x0012,
    "long int": 0x0012,
    "signed long": 0x0012,
    "unsigned long": 0x0022,
    "unsigned long int": 0x0022,
    "long long": 0x0013,
    "__int64": 0x0013,
    "unsigned long long": 0x0023,
    "unsigned __int64": 0x0023,
    "float": 0x0040,
    "double": 0x0041,
    "long double": 0x0041,
}
_SIMPLE_SIZES: dict[int, int] = {
    0x0070: 1,
    0x0010: 1,
    0x0020: 1,
    0x0030: 1,
    0x0071: 2,
    0x0011: 2,
    0x0021: 2,
    0x0074: 4,
    0x0075: 4,
    0x0012: 4,
    0x0022: 4,
    0x0013: 8,
    0x0023: 8,
    0x0040: 4,
    0x0041: 8,
}
_QUALIFIERS = frozenset({"const", "volatile"})
#: Simple-type pointer modes (``CV_TM_NPTR32`` / ``CV_TM_NPTR64``).
_PTR_MODE_32 = 0x0400
_PTR_MODE_64 = 0x0600
#: ``LF_POINTER`` attributes: pointer kind (Near32 / Near64) | size << 13.
_PTR_ATTRS_32 = 0x0A | (4 << 13)
_PTR_ATTRS_64 = 0x0C | (8 << 13)
#: Array index types MSVC writes (``T_ULONG`` / ``T_UQUAD``).
_INDEX_TYPE_32 = 0x0022
_INDEX_TYPE_64 = 0x0023
_FIRST_TYPE_INDEX = 0x1000
_NO_TYPE = 0

#: COFF machine → llvm-pdbutil ``MachineType`` name.
_MACHINES = {0x14C: "x86", 0x8664: "Amd64"}

_SUMMARY_GUID = re.compile(r"^\s*GUID:\s*(\{[0-9A-Fa-f-]+\})\s*$", re.M)
_SUMMARY_AGE = re.compile(r"^\s*Age:\s*(\d+)\s*$", re.M)
_SUMMARY_SIGNATURE = re.compile(r"^\s*Signature:\s*(\d+)\s*$", re.M)

# ---------------------------------------------------------------------------
# Target identity
# ---------------------------------------------------------------------------


class PdbExportError(RebrewError, RuntimeError):
    """The PDB cannot be built from these inputs (message names the cause)."""


@dataclass(frozen=True)
class DebugIdentity:
    """What the target's CodeView record says its PDB must carry.

    ``kind`` is ``rsds`` / ``nb10`` / ``none``.  ``guid`` is the braced
    upper-case GUID (zero unless ``rsds``), ``signature`` the NB10 32-bit
    signature (or the image timestamp for ``rsds``), ``pdb_name`` the base
    name of the PDB path the record names, empty when there is none.
    """

    kind: Literal["rsds", "nb10", "none"]
    guid: str = _ZERO_GUID
    signature: int = 0
    age: int = 0
    pdb_name: str = ""


def _pdb_basename(path_text: str) -> str:
    """The file name of a Windows or POSIX PDB path, or '' if it is unusable."""
    if path_text.endswith(("\\", "/")):
        return ""
    name = PureWindowsPath(path_text.replace("/", "\\")).name
    if not name or name in {".", ".."} or any(ord(ch) < 0x20 for ch in name):
        return ""
    return name


def read_debug_identity(pe: Any, image: bytes) -> DebugIdentity:
    """Read the first CodeView record of LIEF-parsed *pe*.

    *image* is the file's bytes.  LIEF decodes RSDS fully, but for NB10 it
    reports the age and path and leaves the 32-bit signature out, so that one
    field is read from *image* at the record's file offset, bounds-checked.
    A truncated or unknown record reads as ``none``.
    """
    import lief

    for entry in pe.debug:
        if not isinstance(entry, lief.PE.CodeViewPDB):
            continue
        signature = entry.cv_signature
        if signature == lief.PE.CodeView.SIGNATURES.PDB_70:
            return DebugIdentity(
                kind="rsds",
                guid="{" + str(entry.guid).upper() + "}",
                signature=int(pe.header.time_date_stamps),
                age=int(entry.age),
                pdb_name=_pdb_basename(str(entry.filename)),
            )
        if signature == lief.PE.CodeView.SIGNATURES.PDB_20:
            offset = int(entry.pointerto_rawdata)
            end = offset + _NB10_HEADER.size
            if offset <= 0 or int(entry.sizeof_data) < _NB10_HEADER.size or end > len(image):
                continue
            magic, _cv_offset, nb10_signature, age = _NB10_HEADER.unpack_from(image, offset)
            if magic != _NB10:
                continue
            return DebugIdentity(
                kind="nb10",
                signature=nb10_signature,
                age=age,
                pdb_name=_pdb_basename(str(entry.filename)),
            )
    return DebugIdentity(kind="none")


# ---------------------------------------------------------------------------
# CodeView types for data symbols
# ---------------------------------------------------------------------------


@dataclass
class TypeTable:
    """TPI records for the data types, deduplicated; indices start at 0x1000."""

    pointer_size: int
    records: list[dict[str, Any]] = field(default_factory=list)
    _index: dict[str, int] = field(default_factory=dict)

    def _add(self, key: str, record: dict[str, Any]) -> int:
        found = self._index.get(key)
        if found is not None:
            return found
        index = _FIRST_TYPE_INDEX + len(self.records)
        self.records.append(record)
        self._index[key] = index
        return index

    def pointer_to(self, referent: int) -> int:
        """A pointer to *referent*: a simple-type mode when it has one."""
        mode = _PTR_MODE_64 if self.pointer_size == 8 else _PTR_MODE_32
        if referent < _FIRST_TYPE_INDEX and not referent & 0xFF00:
            return mode | referent
        attrs = _PTR_ATTRS_64 if self.pointer_size == 8 else _PTR_ATTRS_32
        return self._add(
            f"P{referent}",
            {"Kind": "LF_POINTER", "Pointer": {"ReferentType": referent, "Attrs": attrs}},
        )

    def array_of(self, element: int, total_size: int) -> int:
        """An array of *element* spanning *total_size* bytes."""
        index_type = _INDEX_TYPE_64 if self.pointer_size == 8 else _INDEX_TYPE_32
        return self._add(
            f"A{element}:{total_size}",
            {
                "Kind": "LF_ARRAY",
                "Array": {
                    "ElementType": element,
                    "IndexType": index_type,
                    "Size": total_size,
                    "Name": "",
                },
            },
        )

    def size_of(self, index: int) -> int | None:
        """Byte size of a type this table built or a simple type, else None."""
        if index & 0xFF00 in (_PTR_MODE_32, _PTR_MODE_64) and index < _FIRST_TYPE_INDEX:
            return self.pointer_size
        if index < _FIRST_TYPE_INDEX:
            return _SIMPLE_SIZES.get(index)
        record = self.records[index - _FIRST_TYPE_INDEX]
        if record["Kind"] == "LF_POINTER":
            return self.pointer_size
        size: int = record["Array"]["Size"]
        return size

    def type_for(self, type_text: str, known_size: int | None) -> int:
        """The CodeView type index for C *type_text*, or 0 when unsupported.

        Supported: base types, any pointer depth over them, and arrays of
        either.  An omitted outermost bound (``char[]``) is taken from
        *known_size* when it divides evenly.  Qualifiers are dropped.
        """
        from rebrew.c_parser import array_type_shape

        base, dims = array_type_shape(type_text)
        if "(" in base or ")" in base:
            return _NO_TYPE
        stars = base.count("*")
        words = [w for w in base.replace("*", " ").split() if w not in _QUALIFIERS]
        index = _SIMPLE_TYPES.get(" ".join(words), _NO_TYPE)
        if index == _NO_TYPE or (index == _SIMPLE_TYPES["void"] and not stars and not dims):
            return _NO_TYPE
        for _ in range(stars):
            index = self.pointer_to(index)
        if not dims:
            return index
        element_size = self.size_of(index)
        if element_size is None:
            return _NO_TYPE
        for bound in reversed(dims[1:]):
            if not isinstance(bound, int) or bound <= 0:
                return _NO_TYPE
            element_size *= bound
            index = self.array_of(index, element_size)
        outer = dims[0]
        if outer is None and known_size and known_size % element_size == 0:
            outer = known_size // element_size
        if not isinstance(outer, int) or outer <= 0:
            return _NO_TYPE
        return self.array_of(index, element_size * outer)


# ---------------------------------------------------------------------------
# Symbol collection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DataSymbol:
    """One data label: absolute VA, name, C type spelling, byte size."""

    va: int
    name: str
    type_text: str = ""
    size: int | None = None


def data_symbols(cfg: Any) -> list[DataSymbol]:
    """Annotated globals plus named ``rebrew-data.toml`` rows for the target.

    A source declaration wins over a stored row at the same VA; the row
    fills a size or type the declaration lacks.  Layout spans are byte-range
    bookkeeping, not objects, and are left out, as are unnamed rows.
    """
    from rebrew.data_scan import scan_globals
    from rebrew.metadata.data import load_data_metadata, module_visible_to_target

    by_va: dict[int, DataSymbol] = {}
    scan = scan_globals(cfg.reversed_dir, cfg=cfg, record_roles=False)
    for entry in scan.globals.values():
        if not entry.va or entry.storage_kind == "span" or entry.va in by_va:
            continue
        by_va[entry.va] = DataSymbol(entry.va, entry.name, entry.type_str, entry.size or None)
    for (module, va), fields in load_data_metadata(cfg.metadata_dir).items():
        name = fields.get("name")
        if not isinstance(name, str) or not name or fields.get("storage_kind") == "span":
            continue
        if not module_visible_to_target(module, cfg):
            continue
        row_type = fields.get("type") if isinstance(fields.get("type"), str) else ""
        row_size = fields.get("size") if isinstance(fields.get("size"), int) else None
        known = by_va.get(va)
        if known is None:
            by_va[va] = DataSymbol(va, name, row_type or "", row_size or None)
        else:
            by_va[va] = DataSymbol(
                va, known.name, known.type_text or row_type or "", known.size or row_size or None
            )
    return sorted(by_va.values(), key=lambda d: (d.va, d.name))


def merge_data(
    rows: list[SymbolRow], data: list[DataSymbol]
) -> tuple[list[SymbolRow], dict[int, DataSymbol], list[str]]:
    """Append *data* to the function *rows*; a function wins a VA or name clash.

    Returns the merged rows, the data symbols kept (by VA), and one message
    per dropped symbol.  Functions that clash with each other are dropped the
    same way, first one kept.
    """
    merged: list[SymbolRow] = []
    names: set[str] = set()
    vas: set[int] = set()
    kept: dict[int, DataSymbol] = {}
    collisions: list[str] = []

    def take(row: SymbolRow, what: str) -> bool:
        assert row.va is not None
        if row.va in vas or row.name in names:
            collisions.append(
                f"{row.name} (0x{row.va:08X}, {what}) collides with an earlier symbol"
            )
            return False
        vas.add(row.va)
        names.add(row.name)
        merged.append(row)
        return True

    for row in sorted(rows, key=lambda r: (r.va or 0, r.name)):
        take(row, "function")
    for item in data:
        if take(SymbolRow(va=item.va, name=item.name, kind="data", size=item.size), "data"):
            kept[item.va] = item
    return merged, kept, collisions


# ---------------------------------------------------------------------------
# PDB document
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Section:
    """One PE section header, as the PDB's section-header stream stores it."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_pointer: int
    characteristics: int

    def contains(self, rva: int) -> bool:
        """Whether *rva* falls inside this section's mapped extent."""
        extent = max(self.virtual_size, self.raw_size)
        return self.virtual_address <= rva < self.virtual_address + extent


@dataclass
class PdbPlan:
    """The JSON document for ``yaml2pdb`` plus what went into it."""

    document: dict[str, Any]
    functions: int = 0
    procedures: int = 0
    data: int = 0
    typed_data: int = 0
    outside_sections: list[str] = field(default_factory=list)
    unnamed: list[str] = field(default_factory=list)


def _record_size(fixed: int, name: str) -> int:
    raw = _RECORD_HEADER + fixed + len(name.encode("utf-8")) + 1
    return (raw + _RECORD_ALIGN - 1) // _RECORD_ALIGN * _RECORD_ALIGN


def _locate(sections: list[Section], rva: int) -> tuple[int, Section] | None:
    for number, section in enumerate(sections, start=1):
        if section.contains(rva):
            return number, section
    return None


def build_plan(
    identity: DebugIdentity,
    machine: str,
    image_base: int,
    sections: list[Section],
    rows: list[SymbolRow],
    data: dict[int, DataSymbol],
    pointer_size: int,
) -> PdbPlan:
    """Lay out the ``llvm-pdbutil`` PDB document for *rows*.

    *rows* are placed by VA into *sections* (1-based segment numbers); a row
    outside every section, or whose name holds a NUL (CodeView names are
    NUL-terminated), is reported and left out.  ``S_GPROC32.PtrEnd`` is the
    module-stream offset of its ``S_END``, computed from the record sizes.
    """
    types = TypeTable(pointer_size=pointer_size)
    plan = PdbPlan(document={})
    records: list[dict[str, Any]] = [
        {"Kind": "S_OBJNAME", "ObjNameSym": {"Signature": 0, "ObjectName": _OBJECT_NAME}}
    ]
    offset = _MODULE_STREAM_SIGNATURE + _record_size(_OBJNAME_FIXED, _OBJECT_NAME)
    publics: list[dict[str, Any]] = []
    contribs: list[dict[str, Any]] = []
    for row in sorted(rows, key=lambda r: (r.va or 0, r.name)):
        if row.va is None:
            continue
        if "\x00" in row.name or not row.name:
            plan.unnamed.append(f"0x{row.va:08X}")
            continue
        located = _locate(sections, row.va - image_base)
        if located is None:
            plan.outside_sections.append(f"{row.name}@0x{row.va:08X}")
            continue
        segment, section = located
        sect_offset = row.va - image_base - section.virtual_address
        is_function = row.kind == KIND_FUNC
        display = row.display_name or row.name
        publics.append(
            {
                "Kind": "S_PUB32",
                "PublicSym32": {
                    "Flags": ["Function"] if is_function else [],
                    "Offset": sect_offset,
                    "Segment": segment,
                    "Name": row.name,
                },
            }
        )
        if is_function:
            plan.functions += 1
            if not row.size:
                continue
            plan.procedures += 1
            end = offset + _record_size(_GPROC32_FIXED, display)
            records.append(
                {
                    "Kind": "S_GPROC32",
                    "ProcSym": {
                        "PtrParent": 0,
                        "PtrEnd": end,
                        "PtrNext": 0,
                        "CodeSize": row.size,
                        "DbgStart": 0,
                        "DbgEnd": 0,
                        "FunctionType": _NO_TYPE,
                        "Offset": sect_offset,
                        "Segment": segment,
                        "Flags": [],
                        "DisplayName": display,
                    },
                }
            )
            records.append({"Kind": "S_END", "ScopeEndSym": {}})
            offset = end + _RECORD_HEADER
            contribs.append(
                {
                    "ISect": segment,
                    "Offset": sect_offset,
                    "Size": row.size,
                    "Characteristics": section.characteristics,
                    "Imod": 0,
                    "DataCrc": 0,
                    "RelocCrc": 0,
                    "ISectCoff": 0,
                }
            )
            continue
        plan.data += 1
        item = data.get(row.va)
        type_index = types.type_for(item.type_text, item.size) if item and item.type_text else 0
        if type_index:
            plan.typed_data += 1
        records.append(
            {
                "Kind": "S_GDATA32",
                "DataSym": {
                    "Type": type_index,
                    "Offset": sect_offset,
                    "Segment": segment,
                    "DisplayName": display,
                },
            }
        )
        offset += _record_size(_GDATA32_FIXED, display)
    plan.document = {
        "PdbStream": {
            "Age": identity.age,
            "Guid": identity.guid,
            "Signature": identity.signature,
            "Features": [],
            "Version": "VC70",
        },
        "DbiStream": {
            "VerHeader": "V70",
            "Age": identity.age,
            "BuildNumber": _DBI_BUILD_NUMBER,
            "PdbDllVersion": 0,
            "PdbDllRbld": 0,
            "Flags": 0,
            "MachineType": machine,
            "Modules": [
                {
                    "Module": _OBJECT_NAME,
                    "ObjFile": _OBJECT_NAME,
                    "Modi": {"Signature": _MODULE_STREAM_SIGNATURE, "Records": records},
                }
            ],
            "SectionHeaders": [
                {
                    "Name": s.name,
                    "VirtualSize": s.virtual_size,
                    "VirtualAddress": s.virtual_address,
                    "SizeOfRawData": s.raw_size,
                    "PointerToRawData": s.raw_pointer,
                    "PointerToRelocations": 0,
                    "PointerToLinenumbers": 0,
                    "NumberOfRelocations": 0,
                    "NumberOfLinenumbers": 0,
                    "Characteristics": s.characteristics,
                }
                for s in sections
            ],
            "SectionContribs": {
                "Version": "Ver60",
                "Items": sorted(contribs, key=lambda c: (c["ISect"], c["Offset"])),
            },
        },
        "TpiStream": {"Version": "VC80", "Records": types.records},
        "IpiStream": {"Version": "VC80", "Records": []},
        "PublicsStream": {"Records": publics},
    }
    return plan


# ---------------------------------------------------------------------------
# llvm-pdbutil
# ---------------------------------------------------------------------------


def _pdbutil() -> str:
    tool = shutil.which("llvm-pdbutil")
    if tool is None:
        raise PdbExportError(
            "llvm-pdbutil not found on PATH; install LLVM (it ships llvm-pdbutil) "
            "to write PDB files"
        )
    return tool


def write_pdb(document: dict[str, Any], output: Path) -> None:
    """Assemble *document* into the PDB at *output* (atomically replaced).

    Runs ``llvm-pdbutil yaml2pdb``: no in-process MSF/PDB writer exists.
    It crashes rather than reporting some malformed input, so any non-zero
    exit or missing output is an error carrying its stderr.
    """
    tool = _pdbutil()
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    try:
        try:
            result = subprocess.run(
                [tool, "yaml2pdb", f"-pdb={partial}", "-"],
                input=json.dumps(document),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_PDBUTIL_TIMEOUT_S,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PdbExportError(f"llvm-pdbutil yaml2pdb failed: {exc}") from exc
        if result.returncode != 0 or not partial.is_file():
            detail = (result.stderr or result.stdout).strip().splitlines()[:3]
            raise PdbExportError(
                f"llvm-pdbutil yaml2pdb exited {result.returncode}: " + " | ".join(detail)
            )
        os.replace(partial, output)
    finally:
        partial.unlink(missing_ok=True)


def read_back_identity(pdb: Path) -> tuple[str, int, int]:
    """``(GUID, age, signature)`` of *pdb* per ``llvm-pdbutil dump -summary``."""
    tool = _pdbutil()
    try:
        result = subprocess.run(
            [tool, "dump", "-summary", str(pdb)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_PDBUTIL_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PdbExportError(f"llvm-pdbutil dump failed: {exc}") from exc
    guid = _SUMMARY_GUID.search(result.stdout)
    age = _SUMMARY_AGE.search(result.stdout)
    signature = _SUMMARY_SIGNATURE.search(result.stdout)
    if result.returncode != 0 or not guid or not age or not signature:
        raise PdbExportError(f"llvm-pdbutil cannot read back {pdb}")
    return guid.group(1).upper(), int(age.group(1)), int(signature.group(1))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_target(binary: Path) -> tuple[Any, bytes]:
    import lief

    try:
        image = binary.read_bytes()
    except OSError as exc:
        raise PdbExportError(f"cannot read target binary {binary}: {exc}") from exc
    pe = lief.PE.parse(list(image))
    if pe is None:
        raise PdbExportError(f"target binary is not a PE image: {binary}")
    return pe, image


def _sections(pe: Any) -> list[Section]:
    return [
        Section(
            name=str(s.name),
            virtual_address=int(s.virtual_address),
            virtual_size=int(s.virtual_size),
            raw_size=int(s.sizeof_raw_data),
            raw_pointer=int(s.pointerto_raw_data),
            characteristics=int(s.characteristics),
        )
        for s in pe.sections
    ]


@app.callback(invoke_without_command=True)
def main(
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path (default: the PDB file name the target's debug record names)",
    ),
    pe_symbol_output: bool = typer.Option(
        False, "--pe-symbols", help="Include symbols named from the target PE's data directories"
    ),
    unmatched: bool = typer.Option(
        False,
        "--unmatched",
        help="Write a PDB with zero identifiers when the target has no CodeView record",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Write a PDB carrying rebrew's names, sizes, and data types for the target."""
    cfg = require_config(target=target, json_mode=json_output)
    binary = Path(cfg.target_binary)
    try:
        pe, image = _load_target(binary)
        machine = _MACHINES.get(int(pe.header.machine.value))
        if machine is None:
            raise PdbExportError(
                f"unsupported PE machine 0x{int(pe.header.machine.value):X} (x86 and x64 only)"
            )
        identity = read_debug_identity(pe, image)
        if identity.kind == "none" and not unmatched:
            raise PdbExportError(
                "the target has no CodeView debug record, so no PDB can match it; pass "
                "--unmatched to write one with zero identifiers and load it by hand"
            )
        out_path = output or Path(identity.pdb_name or f"{binary.stem}.pdb")

        functions, skipped_unnamed, skipped_va = function_symbol_rows(cfg)
        rows, kept_data, collisions = merge_data(functions, data_symbols(cfg))
        pe_count = 0
        if pe_symbol_output:
            table = pe_symbols(binary)
            pe_count = len(table.symbols)
            rows, pe_collisions = merge_pe_symbols(rows, table)
            collisions += pe_collisions
        pointer_size = 8 if machine == "Amd64" else 4
        plan = build_plan(
            identity,
            machine,
            int(pe.optional_header.imagebase),
            _sections(pe),
            rows,
            kept_data,
            pointer_size,
        )
        write_pdb(plan.document, out_path)
        guid, age, signature = read_back_identity(out_path)
    except PdbExportError as exc:
        error_exit(str(exc), json_mode=json_output, code=EXIT_ERROR)
    if (guid, age, signature) != (identity.guid, identity.age, identity.signature):
        error_exit(
            f"{out_path} reads back as {guid} age {age} signature {signature}, "
            f"not {identity.guid} age {identity.age} signature {identity.signature}",
            json_mode=json_output,
            code=EXIT_ERROR,
        )

    warnings: list[str] = []
    if identity.kind == "nb10":
        warnings.append(
            "the target names a PDB 2.0 file (NB10); this PDB 7.0 file carries its "
            "signature and age, but tools that match 7.0 files by GUID (Ghidra) "
            "report a mismatch and need a forced load"
        )
    elif identity.kind == "none":
        warnings.append("no CodeView record: identifiers are zero; load this PDB by hand")
    payload = {
        "output": str(out_path),
        "identity": {
            "kind": identity.kind,
            "guid": identity.guid,
            "signature": identity.signature,
            "age": identity.age,
            "pdb_name": identity.pdb_name,
        },
        "functions": plan.functions,
        "functions_with_size": plan.procedures,
        "data": plan.data,
        "typed_data": plan.typed_data,
        "type_records": len(plan.document["TpiStream"]["Records"]),
        "pe_symbols": pe_count,
        "skipped_unnamed": skipped_unnamed,
        "skipped_invalid_va": skipped_va,
        "outside_sections": plan.outside_sections,
        "collisions": collisions,
        "warnings": warnings,
    }
    if json_output:
        json_print(payload)
        return
    for collision in collisions:
        console.print(f"[yellow]symbol dropped:[/yellow] {untrusted_ident(collision)}")
    if plan.outside_sections:
        console.print(
            f"[yellow]{len(plan.outside_sections)} symbol(s) outside every section dropped:"
            f"[/yellow] " + ", ".join(untrusted_ident(s) for s in plan.outside_sections[:8])
        )
    for warning in warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    console.print(
        f"[green]Wrote {untrusted_ident(out_path)}[/green]: {plan.functions} function(s) "
        f"({plan.procedures} sized), {plan.data} data symbol(s) ({plan.typed_data} typed); "
        f"{identity.kind.upper()} {identity.guid} age {identity.age}"
    )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
