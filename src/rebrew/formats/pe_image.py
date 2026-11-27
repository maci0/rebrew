"""PE32 image walk and the MSVC link options read off it.

Sections, exports, imports, and the header fields that map onto LINK
options (``/BASE``, ``/ALIGN``, ``/SUBSYSTEM``, ``/STACK``, ``/HEAP``).
This stays out of :mod:`rebrew.buildsys.gen_layout` so a caller can parse a
reference binary without importing that Typer command — and the CLI
graph under it.  :func:`rebrew.buildsys.layout_meta.extract_layout` walks the
same export and import tables for the text layout package; the two
agree on exports and on resolved imports.
"""

from __future__ import annotations

from dataclasses import dataclass
lazy import io
lazy from typing import Any

lazy from rebrew.formats.pe_headers import pe_header

#: Cap on import name-table / descriptor slots read from one PE.
_MAX_IMPORT_SLOTS = 65536

#: Cap on export AddressOfFunctions / AddressOfNames entries.
_MAX_EXPORT_ENTRIES = 65536


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
class PeImport:
    """One PE import: the DLL plus a name, or an ordinal when unnamed."""

    dll: str
    name: str | None  # None = ordinal-only
    ordinal: int | None


def parse_pe(
    data: bytes,
) -> tuple[list[_Section], list[dict[str, Any]], list[PeImport], dict[str, Any]]:
    """Return (sections, exports, imports, pe_params) from a PE32 image via LIEF."""
    import lief

    # Enforce PE32-only + header-fits-in-file validation consistently with
    # layout_meta.extract_layout before handing untrusted bytes to LIEF.
    e, nsec, optsz, _opt, image_base = pe_header(data)
    header_size = e + 4 + 20 + optsz + nsec * 40
    if header_size > len(data):
        raise ValueError("PE section table extends past EOF")

    binary = lief.PE.parse(io.BytesIO(data))
    if binary is None:
        raise ValueError("not a PE32 binary")

    hdr = binary.header
    opt = binary.optional_header
    sections: list[_Section] = [
        _Section(
            s.name.decode("latin1") if isinstance(s.name, bytes) else str(s.name),
            int(s.virtual_address),
            int(s.virtual_size),
            int(s.sizeof_raw_data),
            int(s.pointerto_raw_data),
            int(s.characteristics),
        )
        for s in binary.sections
    ]

    # ---- exports ----
    exports: list[dict[str, Any]] = []
    exp = binary.get_export()
    if exp is not None:
        # Materialize LIEF iterator before any early break to avoid nanobind refleaks.
        for entry in list(exp.entries):
            if len(exports) >= _MAX_EXPORT_ENTRIES:
                break
            if entry.is_forwarded or not entry.address:
                continue
            exports.append(
                {
                    "name": entry.name or None,
                    "ordinal": int(entry.ordinal),
                    "va": image_base + int(entry.address),
                }
            )

    # ---- imports (IAT order, per DLL descriptor) ----
    imports: list[PeImport] = []
    import_slots = 0
    for imp in list(binary.imports):
        raw_dll = imp.name
        dll = raw_dll.decode("latin1") if isinstance(raw_dll, bytes) else (raw_dll or "?")
        for imp_entry in list(imp.entries):
            import_slots += 1
            if import_slots > _MAX_IMPORT_SLOTS:
                raise ValueError("PE import slot limit exceeded")
            if imp_entry.is_ordinal:
                imports.append(PeImport(dll, None, int(imp_entry.ordinal) & 0xFFFF))
            elif imp_entry.name:
                raw_name = imp_entry.name
                name = raw_name.decode("latin1") if isinstance(raw_name, bytes) else str(raw_name)
                imports.append(PeImport(dll, name, None))

    # ---- PE normalization params ----
    reloc_dir = binary.data_directory(lief.PE.DataDirectory.TYPES.BASE_RELOCATION_TABLE)
    reloc_rva = int(reloc_dir.rva) if reloc_dir is not None else 0
    reloc_size = int(reloc_dir.size) if reloc_dir is not None else 0
    reloc_section = next(
        (s for s in sections if s.va <= reloc_rva < s.va + max(s.vs, s.raw_size)), None
    )
    machine_val = hdr.machine
    subsystem_val = opt.subsystem
    pe = {
        "image_base": image_base,
        "e_lfanew": e,
        "header_size": header_size,
        "time_date_stamp": int(hdr.time_date_stamps),
        "checksum": int(opt.checksum),
        "size_of_image": int(opt.sizeof_image),
        "size_of_initialized_data": int(opt.sizeof_initialized_data),
        "base_of_data": int(opt.baseof_data),
        "reloc_rva": reloc_rva,
        "reloc_va": image_base + reloc_rva if reloc_section else None,
        "reloc_size": reloc_size,
        "machine": int(getattr(machine_val, "value", machine_val)),
        "characteristics": int(hdr.characteristics),
        "section_alignment": int(opt.section_alignment),
        "file_alignment": int(opt.file_alignment),
        "subsystem": int(getattr(subsystem_val, "value", subsystem_val)),
        "dll_characteristics": int(opt.dll_characteristics),
        "stack_reserve": int(opt.sizeof_stack_reserve),
        "stack_commit": int(opt.sizeof_stack_commit),
        "heap_reserve": int(opt.sizeof_heap_reserve),
        "heap_commit": int(opt.sizeof_heap_commit),
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
    ``rebrew build round-trip --fix-headers`` consumes).

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
    link.append("# Derived by 'rebrew build layout' from the original binary.")
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
