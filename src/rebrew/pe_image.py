"""PE32 image walk and the MSVC link options read off it.

Sections, exports, imports, and the header fields that map onto LINK
options (``/BASE``, ``/ALIGN``, ``/SUBSYSTEM``, ``/STACK``, ``/HEAP``).
This stays out of :mod:`rebrew.gen_layout` so a caller can parse a
reference binary without importing that Typer command — and the CLI
graph under it.  :func:`rebrew.layout_meta.extract_layout` walks the
same export and import tables for the text layout package; the two
agree on exports and on resolved imports.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from rebrew.pe_headers import pe_lfanew, sections_at

#: Cap on import name-table / descriptor slots read from one PE.  A missing
#: null terminator would otherwise walk past EOF into ``struct.error`` or
#: spin on a wrapped offset; matches ``pe_symbols._MAX_TABLE_ENTRIES``.
_MAX_IMPORT_SLOTS = 65536

#: Cap on export AddressOfFunctions / AddressOfNames entries.  A forged
#: NumberOfNames/NumberOfFunctions of ``0xFFFFFFFF`` would otherwise hang in
#: ``range()`` or raise ``struct.error`` past EOF.
_MAX_EXPORT_ENTRIES = 65536

#: Offset of the last optional-header byte ``parse_pe`` reads unconditionally
#: (basereloc directory size, at optional+140).  SizeOfOptionalHeader can
#: claim fewer bytes than that while the file ends on the claim; the reads
#: would raise ``struct.error``.  Callers catch ``ValueError``.
_OPT_FIELD_END = 144


# ---------------------------------------------------------------------------
# Image parse
# ---------------------------------------------------------------------------


@dataclass
class _Section:
    name: str
    va: int
    vs: int
    raw_size: int
    raw_ptr: int
    characteristics: int


@dataclass
class _Import:
    dll: str
    name: str | None  # None = ordinal-only
    ordinal: int | None


def parse_pe(
    data: bytes,
) -> tuple[list[_Section], list[dict[str, Any]], list[_Import], dict[str, Any]]:
    """Return (sections, exports, imports, pe_params) from a PE image."""
    if len(data) < 0x40:
        raise ValueError("file too small to be a PE")
    e = pe_lfanew(data)
    if e is None or e + 24 > len(data):
        raise ValueError("no PE signature")
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    optsz = struct.unpack_from("<H", data, e + 20)[0]
    opt = e + 24
    if opt + optsz > len(data) or opt + _OPT_FIELD_END > len(data):
        raise ValueError("truncated optional header")
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x10B:
        raise ValueError(f"unsupported optional-header magic 0x{magic:x} (PE32+ not supported)")
    image_base = struct.unpack_from("<I", data, opt + 28)[0]
    timestamp = struct.unpack_from("<I", data, e + 8)[0]  # COFF TimeDateStamp
    checksum = struct.unpack_from("<I", data, opt + 64)[0]
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    size_of_init_data = struct.unpack_from("<I", data, opt + 8)[0]
    base_of_data = struct.unpack_from("<I", data, opt + 24)[0]
    # remaining optional-header fields (for link-option derivation)
    machine = struct.unpack_from("<H", data, e + 4)[0]
    coff_chars = struct.unpack_from("<H", data, e + 4 + 18)[0]
    section_align = struct.unpack_from("<I", data, opt + 32)[0]
    file_align = struct.unpack_from("<I", data, opt + 36)[0]
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    dll_chars = struct.unpack_from("<H", data, opt + 70)[0]
    stack_reserve = struct.unpack_from("<I", data, opt + 72)[0]
    stack_commit = struct.unpack_from("<I", data, opt + 76)[0]
    heap_reserve = struct.unpack_from("<I", data, opt + 80)[0]
    heap_commit = struct.unpack_from("<I", data, opt + 84)[0]
    sh = opt + optsz
    # Same guard as layout_meta.parse_pe: callers catch ValueError, so a
    # short section table must not escape as struct.error.
    if sh + 40 * nsec > len(data):
        raise ValueError("truncated section table")

    def rva_to_off(rva: int) -> int | None:
        for s in sections:
            span = max(s.vs, s.raw_size)
            if s.va <= rva < s.va + span:
                return s.raw_ptr + (rva - s.va)
        return None

    sections: list[_Section] = [
        _Section(
            s.name,
            s.virtual_address,
            s.virtual_size,
            s.size_of_raw_data,
            s.pointer_to_raw_data,
            s.characteristics,
        )
        for s in sections_at(data, sh, nsec)
    ]

    def cstr(off: int | None) -> str | None:
        if off is None or off >= len(data):
            return None
        end = data.find(b"\0", off)
        if end < 0:
            # Unterminated — read to EOF.  ``data[off:-1]`` would drop the
            # last byte (same trap layout_meta already guards against).
            end = len(data)
        return data[off:end].decode("latin1", "replace")

    # ---- exports ----
    exp_rva, exp_sz = struct.unpack_from("<II", data, opt + 96)
    exports: list[dict[str, Any]] = []
    eo = rva_to_off(exp_rva)
    # IMAGE_EXPORT_DIRECTORY is 40 bytes; require the full header before
    # reading counts / RVAs, and cap table walks like the import path.
    if eo is not None and exp_sz and eo + 40 <= len(data):
        nfuncs = min(struct.unpack_from("<I", data, eo + 20)[0], _MAX_EXPORT_ENTRIES)
        nnames = min(struct.unpack_from("<I", data, eo + 24)[0], _MAX_EXPORT_ENTRIES)
        funcs_off = rva_to_off(struct.unpack_from("<I", data, eo + 28)[0])
        names_off = rva_to_off(struct.unpack_from("<I", data, eo + 32)[0])
        ords_off = rva_to_off(struct.unpack_from("<I", data, eo + 36)[0])
        ordinal_base = struct.unpack_from("<I", data, eo + 16)[0]
        name_by_ord: dict[int, str] = {}
        for i in range(nnames):
            if names_off is not None and names_off + 4 * (i + 1) > len(data):
                break
            if ords_off is not None and ords_off + 2 * (i + 1) > len(data):
                break
            nrva = struct.unpack_from("<I", data, names_off + 4 * i)[0] if names_off else 0
            ord_idx = struct.unpack_from("<H", data, ords_off + 2 * i)[0] if ords_off else 0
            nm = cstr(rva_to_off(nrva))
            if nm:
                name_by_ord[ordinal_base + ord_idx] = nm
        for i in range(nfuncs):
            if funcs_off is not None and funcs_off + 4 * (i + 1) > len(data):
                break
            addr = struct.unpack_from("<I", data, funcs_off + 4 * i)[0] if funcs_off else 0
            if addr == 0:
                continue  # true null entry: no function at this ordinal
            if exp_rva <= addr < exp_rva + exp_sz:
                continue  # forwarder: the RVA points at a forwarder string
                # inside the export directory, not at code
            ordinal = ordinal_base + i
            exports.append(
                {
                    "name": name_by_ord.get(ordinal),
                    "ordinal": ordinal,
                    "va": image_base + addr,
                }
            )

    # ---- imports (IAT order, per DLL descriptor) ----
    imp_rva, imp_sz = struct.unpack_from("<II", data, opt + 104)
    imports: list[_Import] = []
    io = rva_to_off(imp_rva)
    if io is not None:
        for i in range(_MAX_IMPORT_SLOTS):
            ent = io + i * 20
            if ent + 20 > len(data):
                break
            oft_rva, _ts, _fwd, name_rva, iat_rva = struct.unpack_from("<IIIII", data, ent)
            if oft_rva == 0 and name_rva == 0:
                break
            dll = cstr(rva_to_off(name_rva)) or "?"
            # An unbound descriptor (OFT == 0) carries its names in the IAT
            # itself, so the IAT array is the lookup table (the same fallback
            # layout_meta.extract_layout uses).  Reading only the OFT left such
            # a DLL's imports empty: no /include pragmas in the emitted
            # crt_imports.c and an empty `imports` list in layout_config_dict.
            lookup_rva = oft_rva or iat_rva
            oo = rva_to_off(lookup_rva)
            if oo is None:
                continue
            for j in range(_MAX_IMPORT_SLOTS):
                slot_off = oo + 4 * j
                if slot_off + 4 > len(data):
                    break
                nm = struct.unpack_from("<I", data, slot_off)[0]
                if nm == 0:
                    break
                if nm & 0x80000000:
                    imports.append(_Import(dll, None, nm & 0xFFFF))
                else:
                    # hint/name: 2-byte hint + NUL-terminated name
                    no = rva_to_off(nm)
                    imports.append(_Import(dll, cstr(no + 2 if no is not None else None), None))

    # ---- PE normalization params ----
    reloc_rva = struct.unpack_from("<I", data, opt + 96 + 5 * 8)[0]
    reloc_section = next(
        (s for s in sections if s.va <= reloc_rva < s.va + max(s.vs, s.raw_size)), None
    )
    pe = {
        "image_base": image_base,
        "e_lfanew": e,
        # full header block from file offset 0: DOS stub + PE sig + COFF +
        # optional header + section table (ends at e + 0x198)
        "header_size": e + 4 + 20 + optsz + nsec * 40,
        "time_date_stamp": timestamp,
        "checksum": checksum,
        "size_of_image": size_of_image,
        "size_of_initialized_data": size_of_init_data,
        "base_of_data": base_of_data,
        "reloc_rva": reloc_rva,
        "reloc_va": image_base + reloc_rva if reloc_section else None,
        "reloc_size": struct.unpack_from("<I", data, opt + 96 + 5 * 8 + 4)[0],
        # link-option derivation inputs
        "machine": machine,
        "characteristics": coff_chars,
        "section_alignment": section_align,
        "file_alignment": file_align,
        "subsystem": subsystem,
        "dll_characteristics": dll_chars,
        "stack_reserve": stack_reserve,
        "stack_commit": stack_commit,
        "heap_reserve": heap_reserve,
        "heap_commit": heap_commit,
    }
    return sections, exports, imports, pe


# ---------------------------------------------------------------------------
# LINK options read off the parsed header
# ---------------------------------------------------------------------------


def derive_link_options(pe: dict[str, Any]) -> tuple[list[str], str]:
    """Derive MSVC6 LINK options and a ``[link]`` toml block from the reference.

    Most PE header fields map 1:1 onto linker options, so they can be read
    straight off the binary and handed to the linker instead of post-fixed:

      ImageBase      -> /BASE            Subsystem        -> /SUBSYSTEM
      SectionAlign   -> /ALIGN           StackReserve/Commit -> /STACK
      FileAlign      -> /ALIGN:filealign (VC6 derives it)  HeapReserve/Commit -> /HEAP
      CheckSum!=0    -> /RELEASE         Characteristics 0x20 -> /LARGEADDRESSAWARE
      Machine        -> /MACHINE

    Returns ``(link_options, link_toml)`` — the option strings for the link
    line, and a ``[link]`` block for ``rebrew-project.toml`` (the fields
    ``rebrew round-trip --fix-headers`` consumes).

    The options are emitted as *deltas from the VC6 linker defaults*: adding
    an option that equals the default can change fields the default leaves
    alone (e.g. ``/ALIGN:0x1000`` is NOT a no-op — it forces FileAlignment to
    0x200 and shrinks SizeOfHeaders, while the plain default produces
    FileAlignment=0x1000).  Only emit what the original deviates on.
    """
    # VC6 LINK defaults (empirically verified against a plain /dll link)
    DEF_IMAGE_BASE = 0x400000
    DEF_SECTION_ALIGN = 0x1000
    DEF_SUBSYSTEM = 2  # WINDOWS
    DEF_STACK_RESERVE = 0x100000
    DEF_STACK_COMMIT = 0x1000
    DEF_HEAP_RESERVE = 0x100000
    DEF_HEAP_COMMIT = 0x1000
    DEF_MACHINE = 0x14C  # I386

    opts: list[str] = []
    if pe.get("image_base") != DEF_IMAGE_BASE:
        opts.append(f"/BASE:0x{pe['image_base']:x}")
    if pe.get("section_alignment") and pe["section_alignment"] != DEF_SECTION_ALIGN:
        opts.append(f"/ALIGN:0x{pe['section_alignment']:x}")
    sub = pe.get("subsystem") or DEF_SUBSYSTEM
    if sub != DEF_SUBSYSTEM:
        subsys = {1: "NATIVE", 2: "WINDOWS", 3: "CONSOLE", 9: "WINDOWSCE"}.get(sub, f"{sub}")
        opts.append(f"/SUBSYSTEM:{subsys}")

    # ``.get(key) or DEF`` treated a legitimate 0 as "absent" and dropped the
    # option, so the built binary never matched a reference whose field is 0.
    def _size(key: str, default: int) -> int:
        value = pe.get(key)
        return default if value is None else int(value)

    stack_reserve, stack_commit = (
        _size("stack_reserve", DEF_STACK_RESERVE),
        _size("stack_commit", DEF_STACK_COMMIT),
    )
    if (stack_reserve, stack_commit) != (DEF_STACK_RESERVE, DEF_STACK_COMMIT):
        opts.append(f"/STACK:0x{stack_reserve:x},0x{stack_commit:x}")
    heap_reserve, heap_commit = (
        _size("heap_reserve", DEF_HEAP_RESERVE),
        _size("heap_commit", DEF_HEAP_COMMIT),
    )
    if (heap_reserve, heap_commit) != (DEF_HEAP_RESERVE, DEF_HEAP_COMMIT):
        opts.append(f"/HEAP:0x{heap_reserve:x},0x{heap_commit:x}")
    if pe.get("characteristics", 0) & 0x20:
        opts.append("/LARGEADDRESSAWARE")
    if (pe.get("machine") or DEF_MACHINE) != DEF_MACHINE:
        mach = {0x14C: "I386", 0x8664: "X64", 0x1C0: "ARM"}.get(
            pe["machine"], f"0x{pe['machine']:x}"
        )
        opts.append(f"/MACHINE:{mach}")

    link = []
    link.append("[link]")
    link.append("# Derived by 'rebrew gen-layout' from the original binary.")
    if pe.get("file_alignment"):
        link.append(f'file_align = "0x{pe["file_alignment"]:x}"')
    if stack_reserve != DEF_STACK_RESERVE:
        link.append(f'stack_reserve = "0x{stack_reserve:x}"')
    if stack_commit != DEF_STACK_COMMIT:
        link.append(f'stack_commit = "0x{stack_commit:x}"')
    if pe.get("dll_characteristics", 0) & 0x8000:
        link.append("tsaware = true")
    link.append(f'timestamp = "0x{pe["time_date_stamp"]:x}"')
    return opts, "\n".join(link) + "\n"
