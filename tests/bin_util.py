"""Shared helper: hand-rolled COFF/PE binary builders for tests.

LIEF has no binary builders in this version, so tests that need real COFF
objects or PE files (relocation parsing, FLIRT .pat generation, round-trip,
catalog) construct the bytes directly.  The layouts below are the minimum
LIEF will accept.

Imports from a tests/ file work because pytest inserts the test directory
into ``sys.path``.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence

_TEXT_CHARS = 0x60000020  # CODE | EXECUTE | READ | CNT_CODE

_EXTERNAL = 2  # IMAGE_SYM_CLASS_EXTERNAL
_STATIC = 3  # IMAGE_SYM_CLASS_STATIC


def make_pe(
    code: bytes,
    *,
    image_base: int = 0x400000,
    text_va: int = 0x1000,
    imports: list[tuple[str, list[str]]] | None = None,
) -> bytes:
    """Build a minimal PE with one real ``.text`` section containing *code*.

    Layout: DOS header + "PE\0\0" + COFF header + PE32 optional header +
    one section table entry + raw section data at 0x200.  LIEF parses this
    into a ``BinaryInfo`` with ``.text`` at ``image_base + text_va`` whose
    raw file offset is 0x200.

    With *imports* (a list of ``(dll_name, [api_name, ...])``), an import
    directory is appended after *code* inside the same section and wired into
    optional-header data directory 1, so ``lief.PE.parse`` recovers the
    import table (IAT slot RVAs via ``ImportEntry.iat_address``).
    """
    sec_align, file_align, sizeof_headers = 0x1000, 0x200, 0x200

    import_blob, import_dir_rva, import_dir_size = _build_import_directory(
        text_va, len(code), imports
    )
    section_data = code + import_blob
    raw_size = ((len(section_data) + file_align - 1) // file_align) * file_align
    raw = section_data + b"\x00" * (raw_size - len(section_data))
    size_of_image = ((text_va + len(section_data) + sec_align - 1) // sec_align) * sec_align

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)

    opt = bytearray(struct.pack("<H", 0x10B))  # Magic PE32
    opt += struct.pack("<BB", 8, 0)  # linker versions
    opt += struct.pack("<I", len(code))  # SizeOfCode
    opt += struct.pack("<I", 0)  # SizeOfInitializedData
    opt += struct.pack("<I", 0)  # SizeOfUninitializedData
    opt += struct.pack("<I", text_va)  # AddressOfEntryPoint
    opt += struct.pack("<I", text_va)  # BaseOfCode
    opt += struct.pack("<I", 0)  # BaseOfData
    opt += struct.pack("<I", image_base)  # ImageBase
    opt += struct.pack("<I", sec_align)  # SectionAlignment
    opt += struct.pack("<I", file_align)  # FileAlignment
    opt += struct.pack("<HH", 6, 0)  # OS version
    opt += struct.pack("<HH", 0, 0)  # Image version
    opt += struct.pack("<HH", 6, 0)  # Subsystem version
    opt += struct.pack("<I", 0)  # Win32VersionValue
    opt += struct.pack("<I", size_of_image)  # SizeOfImage
    opt += struct.pack("<I", sizeof_headers)  # SizeOfHeaders
    opt += struct.pack("<I", 0)  # CheckSum
    opt += struct.pack("<H", 3)  # Subsystem (console)
    opt += struct.pack("<H", 0)  # DllCharacteristics
    opt += struct.pack("<I", 0x100000)  # SizeOfStackReserve
    opt += struct.pack("<I", 0x1000)  # SizeOfStackCommit
    opt += struct.pack("<I", 0x100000)  # SizeOfHeapReserve
    opt += struct.pack("<I", 0x1000)  # SizeOfHeapCommit
    opt += struct.pack("<I", 0)  # LoaderFlags
    opt += struct.pack("<I", 16)  # NumberOfRvaAndSizes
    opt += b"\x00" * (16 * 8)  # data directories
    if imports:
        # Data directory 1 = import table (RVA, size) at offset 0x68 in opt.
        struct.pack_into("<II", opt, 0x68, import_dir_rva, import_dir_size)
    assert len(opt) == 0xE0

    sec = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        len(section_data),  # VirtualSize
        text_va,  # VirtualAddress
        raw_size,  # SizeOfRawData
        sizeof_headers,  # PointerToRawData
        0,
        0,
        0,
        0,
        _TEXT_CHARS,
    )
    assert len(sec) == 40

    hdrs = dos + b"PE\x00\x00" + coff + opt + sec
    assert len(hdrs) <= sizeof_headers
    hdrs += b"\x00" * (sizeof_headers - len(hdrs))
    return bytes(hdrs + raw)


def _build_import_directory(
    text_va: int,
    code_len: int,
    imports: list[tuple[str, list[str]]] | None,
) -> tuple[bytes, int, int]:
    """Build the import directory blob; returns (blob, dir_rva, dir_size).

    Blob layout (all RVAs relative to ``text_va + code_len``):
    import descriptors (20B each + terminator), then per library:
    INT array, IAT array, hint/name entries, DLL name string.
    """
    if not imports:
        return b"", 0, 0

    base = text_va + code_len
    blob = bytearray()
    # Descriptor area first: one 20-byte descriptor per library + terminator.
    desc_start = 0
    desc_entries: list[tuple[int, int, int]] = []  # (int_rva, name_rva, iat_rva)
    blob += b"\x00" * (20 * len(imports) + 20)
    for dll_name, apis in imports:
        int_rva = base + len(blob)
        blob += b"\x00" * (4 * (len(apis) + 1))
        iat_rva = base + len(blob)
        blob += b"\x00" * (4 * (len(apis) + 1))
        hint_rvas: list[int] = []
        for api in apis:
            hint_rva = base + len(blob)
            hint_rvas.append(hint_rva)
            entry = struct.pack("<H", 0) + api.encode("ascii") + b"\x00"
            if len(entry) % 2:
                entry += b"\x00"
            blob += entry
        name_rva = base + len(blob)
        blob += dll_name.encode("ascii") + b"\x00"
        # Fill the INT and IAT arrays.
        for i, rva in enumerate(hint_rvas):
            struct.pack_into("<I", blob, int_rva - base + 4 * i, rva)
            struct.pack_into("<I", blob, iat_rva - base + 4 * i, rva)
        desc_entries.append((int_rva, name_rva, iat_rva))

    # Fill the descriptor table.
    for i, (int_rva, name_rva, iat_rva) in enumerate(desc_entries):
        off = desc_start + 20 * i
        struct.pack_into("<IIIII", blob, off, int_rva, 0, 0, name_rva, iat_rva)

    return bytes(blob), base, 20 * len(imports) + 20


def make_coff_obj(
    code: bytes,
    *,
    relocs: list[tuple[int, int, str]] | None = None,
    section_chars: int = _TEXT_CHARS,
    func_symbol: str = "_myfunc",
    func_value: int = 0,
    section_symbols: list[tuple[str, int]] | None = None,
    extra_funcs: list[tuple[str, int]] | None = None,
) -> bytes:
    """Build a minimal valid COFF .obj blob in memory.

    Args:
        code: Raw bytes of the section data.
        relocs: ``(offset_in_section, reloc_type, target_symbol)`` triples.
            Each target symbol is added as an undefined external.
        section_chars: Section characteristics (default: code section).
        func_symbol: Name of the section-defined external function (symbol 0).
        func_value: Byte offset of the function within the section.
        section_symbols: ``(name, value)`` pairs of STATIC section symbols
            (e.g. MSVC ``$SG``/``??_C@`` string constants in ``.rdata``),
            added after the reloc targets.
        extra_funcs: ``(name, value)`` pairs of additional EXTERNAL function
            symbols in the same section, appended after the reloc targets
            (so reloc symbol indices stay 1:1 with the reloc list).  These
            delimit ``func_end`` for the primary function and are yielded by
            ``gen_flirt_pat.parse_coff_obj``.

    The returned blob has one section; symbol 0 is *func_symbol* (EXTERNAL,
    section 1, value *func_value*); each reloc target is an additional
    EXTERNAL undefined symbol (string-table name when longer than 8 chars).
    """
    relocs = relocs or []
    section_symbols = section_symbols or []
    extra_funcs = extra_funcs or []

    # Pad code to 4-byte alignment.
    pad_len = (4 - len(code) % 4) % 4
    padded_code = code + b"\x00" * pad_len

    # Offsets.
    off_file_hdr = 0
    off_sec_hdr = off_file_hdr + 20
    off_sec_data = off_sec_hdr + 40
    num_relocs = len(relocs)
    off_relocs = off_sec_data + len(padded_code)
    reloc_bytes = num_relocs * 10
    off_symtab = off_relocs + reloc_bytes

    # String table: names longer than 8 chars.
    long_names = [name for _, _, name in relocs if len(name.encode("ascii")) > 8]
    long_names += [n for n, _ in section_symbols if len(n.encode("ascii")) > 8]
    long_names += [n for n, _ in extra_funcs if len(n.encode("ascii")) > 8]
    strtab_strings = b"".join(n.encode("ascii") + b"\x00" for n in long_names)
    strtab_size = 4 + len(strtab_strings)
    strtab = struct.pack("<I", strtab_size) + strtab_strings
    strtab_offsets = {}
    cursor = 4
    for name in long_names:
        strtab_offsets[name] = cursor
        cursor += len(name.encode("ascii")) + 1

    # --- File header ---
    num_syms = 1 + num_relocs + len(section_symbols) + len(extra_funcs)
    file_hdr = struct.pack(
        "<HHIIIHH",
        0x014C,  # Machine: IMAGE_FILE_MACHINE_I386
        1,  # NumberOfSections
        0,  # TimeDateStamp
        off_symtab,  # PointerToSymbolTable
        num_syms,  # NumberOfSymbols
        0,  # SizeOfOptionalHeader
        0,  # Characteristics
    )
    assert len(file_hdr) == 20

    # --- Section header ---
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0,  # VirtualSize
        0,  # VirtualAddress
        len(padded_code),  # SizeOfRawData
        off_sec_data,  # PointerToRawData
        off_relocs,  # PointerToRelocations
        0,  # PointerToLinenumbers
        num_relocs,  # NumberOfRelocations
        0,  # NumberOfLinenumbers
        section_chars,
    )
    assert len(sec_hdr) == 40

    # --- Relocation records ---
    reloc_bytes_out = b""
    for i, (offset, rtype, _name) in enumerate(relocs):
        # Symbol index: 0 is the function; reloc i targets symbol i + 1.
        reloc_bytes_out += struct.pack("<IIH", offset, i + 1, rtype)
    assert len(reloc_bytes_out) == reloc_bytes

    # --- Symbol table ---
    def _symbol(name: str, value: int, section: int, symtype: int, storage: int) -> bytes:
        raw = name.encode("ascii")
        if len(raw) <= 8:
            name_field = raw + b"\x00" * (8 - len(raw))
            return struct.pack("<8sIhHBB", name_field, value, section, symtype, storage, 0)
        return struct.pack("<IIIhHBB", 0, strtab_offsets[name], value, section, symtype, storage, 0)

    symtab = _symbol(func_symbol, func_value, 1, 0x20, _EXTERNAL)
    for _, _, name in relocs:
        symtab += _symbol(name, 0, 0, 0, _EXTERNAL)
    for name, value in extra_funcs:
        symtab += _symbol(name, value, 1, 0x20, _EXTERNAL)
    for name, value in section_symbols:
        symtab += _symbol(name, value, 1, 0x20, _STATIC)

    return file_hdr + sec_hdr + padded_code + reloc_bytes_out + symtab + strtab


def make_lib_archive(members: list[tuple[str, bytes]]) -> bytes:
    """Build a minimal COFF ``.lib`` archive from member name/bytes pairs."""
    out = b"!<arch>\n"
    for name, data in members:
        name_field = (name + "/").encode("ascii")[:15].ljust(16, b" ")
        out += name_field
        out += b"0".ljust(12, b" ")  # timestamp
        out += b"0".ljust(6, b" ")  # owner
        out += b"0".ljust(6, b" ")  # group
        out += b"100644".ljust(8, b" ")  # mode
        out += f"{len(data):<10}".encode("ascii")  # size
        out += b"`\n"
        out += data
        if len(data) % 2:
            out += b"\n"
    return out


def _elf_hash(name: str) -> int:
    """The SysV ELF hash of *name*, the value Elf32_Vernaux.vna_hash carries."""
    value = 0
    for byte in name.encode("ascii"):
        value = (value << 4) + byte
        high = value & 0xF0000000
        if high:
            value ^= high >> 24
        value &= ~high
    return value & 0xFFFFFFFF


def make_elf(
    code: bytes,
    *,
    image_base: int = 0x8048000,
    text_va: int = 0x8049000,
    text_offset: int = 0x1000,
    needed_libraries: Sequence[str] = (),
    imported_symbols: Sequence[tuple[str, str, str]] = (),
) -> bytes:
    """Build a minimal ELF32 (ET_EXEC, EM_386) with one real ``.text`` section.

    Layout: ELF header + one PT_LOAD program header + raw code at
    *text_offset* + ``.shstrtab`` + a 3-entry section header table.  LIEF
    parses this into a ``BinaryInfo`` with ``.text`` at *text_va* and
    ``image_base`` = the PT_LOAD vaddr.

    *needed_libraries* and *imported_symbols* (``(symbol, library, version)``
    triples) add the dynamic tables a real image uses: ``.dynstr``,
    ``.dynsym``, ``.gnu.version``, ``.gnu.version_r`` with one requirement per
    library, a ``.got.plt`` with one relocation per symbol, ``.dynamic`` with
    the DT_NEEDED/DT_SYMTAB/DT_VERNEED tags and a PT_DYNAMIC segment.  Passing
    neither leaves the output byte-identical to the plain fixture.
    """
    code = bytes(code)
    if not imported_symbols and not needed_libraries:
        return _make_plain_elf(
            code, image_base=image_base, text_va=text_va, text_offset=text_offset
        )
    return _make_dynamic_elf(
        code,
        image_base=image_base,
        text_va=text_va,
        text_offset=text_offset,
        needed_libraries=tuple(needed_libraries),
        imported_symbols=tuple(imported_symbols),
    )


def _make_plain_elf(code: bytes, *, image_base: int, text_va: int, text_offset: int) -> bytes:
    shstrtab = b"\x00.text\x00.shstrtab\x00"
    shstr_off = text_offset + len(code)
    # Pad section data to 4-byte alignment.
    shstr_off = (shstr_off + 3) & ~3
    shoff = shstr_off + len(shstrtab)
    shoff = (shoff + 3) & ~3
    filesz = shoff + 3 * 40

    e_ident = b"\x7fELF" + b"\x01\x01\x01" + b"\x00" * 9
    hdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        e_ident,
        2,  # e_type: ET_EXEC
        3,  # e_machine: EM_386
        1,  # e_version
        text_va,  # e_entry
        52,  # e_phoff
        shoff,  # e_shoff
        0,  # e_flags
        52,  # e_ehsize
        32,  # e_phentsize
        1,  # e_phnum
        40,  # e_shentsize
        3,  # e_shnum
        2,  # e_shstrndx
    )
    phdr = struct.pack(
        "<IIIIIIII",
        1,  # p_type: PT_LOAD
        0,  # p_offset
        image_base,  # p_vaddr
        image_base,  # p_paddr
        filesz,  # p_filesz
        filesz,  # p_memsz
        7,  # p_flags: R|W|X
        0x1000,  # p_align
    )

    def _shdr(name: int, sh_type: int, flags: int, addr: int, offset: int, size: int) -> bytes:
        return struct.pack(
            "<IIIIIIIIII", name, sh_type, flags, addr, offset, size, 0, 0, 16 if size else 0, 0
        )

    shdrs = b"".join(
        [
            b"\x00" * 40,  # null section
            _shdr(1, 1, 0x6, text_va, text_offset, len(code)),  # .text PROGBITS|ALLOC|EXEC
            _shdr(7, 3, 0x0, 0, shstr_off, len(shstrtab)),  # .shstrtab STRTAB
        ]
    )

    out = bytearray(hdr + phdr)
    out += b"\x00" * (text_offset - len(out))
    out += code
    out += b"\x00" * (shstr_off - len(out))
    out += shstrtab
    out += b"\x00" * (shoff - len(out))
    out += shdrs
    return bytes(out)


def _make_dynamic_elf(
    code: bytes,
    *,
    image_base: int,
    text_va: int,
    text_offset: int,
    needed_libraries: tuple[str, ...],
    imported_symbols: tuple[tuple[str, str, str], ...],
) -> bytes:
    """Build the dynamic variant of :func:`make_elf` (see its docstring)."""
    # .dynstr: the leading null, then library names, version names and symbol
    # names, each interned once.
    dynstr = bytearray(b"\x00")
    library_offsets: dict[str, int] = {}
    for library in needed_libraries:
        if library not in library_offsets:
            library_offsets[library] = len(dynstr)
            dynstr += library.encode("ascii") + b"\x00"
    # Version index 1 is the unversioned global base every image has, so the
    # requirement indices the version table refers to start at 2.
    version_offsets: dict[tuple[str, str], int] = {}
    version_indices: dict[tuple[str, str], int] = {}
    for _symbol, library, version in imported_symbols:
        if library and library not in library_offsets:
            library_offsets[library] = len(dynstr)
            dynstr += library.encode("ascii") + b"\x00"
        key = (library, version)
        if version and key not in version_indices and key not in version_offsets:
            version_offsets[key] = len(dynstr)
            dynstr += version.encode("ascii") + b"\x00"
    symbol_offsets: list[int] = []
    for symbol, _library, _version in imported_symbols:
        symbol_offsets.append(len(dynstr))
        dynstr += symbol.encode("ascii") + b"\x00"

    # Version indices in first-appearance order, grouped by the library whose
    # .gnu.version_r requirement declares them.
    library_versions: dict[str, list[tuple[str, str]]] = {}
    for _symbol, library, version in imported_symbols:
        if not version:
            continue
        key = (library, version)
        if key in version_indices:
            continue
        version_indices[key] = 2 + len(version_indices)
        library_versions.setdefault(library, []).append(key)

    symbol_count = len(imported_symbols)
    dynsym = bytearray(b"\x00" * 16)
    for (symbol, _library, _version), offset in zip(imported_symbols, symbol_offsets, strict=True):
        del symbol
        dynsym += struct.pack("<IIIBBH", offset, 0, 0, 0x12, 0, 0)  # GLOBAL FUNC, SHN_UNDEF

    versym = bytearray(struct.pack("<H", 0))
    for _symbol, library, version in imported_symbols:
        index = version_indices.get((library, version), 1) if version else 1
        versym += struct.pack("<H", index)

    # One Verneed per library, its Vernaux list holding that library's
    # versions; vn_aux and vn_next are byte offsets from this Verneed
    # structure, vna_next from the Vernaux itself.
    verneed = bytearray()
    requirement_entries = list(library_versions.items())
    for position, (library, versions) in enumerate(requirement_entries):
        next_offset = 0 if position + 1 == len(requirement_entries) else 16 + 16 * len(versions)
        verneed += struct.pack(
            "<HHIII", 1, len(versions), library_offsets[library], 16, next_offset
        )
        for index, (_library, version) in enumerate(versions):
            last = index + 1 == len(versions)
            verneed += struct.pack(
                "<IHHII",
                _elf_hash(version),
                0,
                version_indices[(library, version)],
                version_offsets[(library, version)],
                0 if last else 16,
            )

    # Section layout: .text, .got.plt, then the dynamic tables.
    def _align(value: int) -> int:
        return (value + 3) & ~3

    got_offset = _align(text_offset + len(code))
    got_size = max(4 * symbol_count, 4)
    dynstr_offset = _align(got_offset + got_size)
    dynsym_offset = _align(dynstr_offset + len(dynstr))
    versym_offset = _align(dynsym_offset + len(dynsym))
    verneed_offset = _align(versym_offset + len(versym))
    rel_offset = _align(verneed_offset + len(verneed))

    # One GOT slot per symbol, and the relocation that resolves it there.
    rel = bytearray()
    for index, (_symbol, _library, _version) in enumerate(imported_symbols):
        rel += struct.pack("<II", image_base + got_offset + 4 * index, (index + 1) << 8 | 7)

    def _va(offset: int) -> int:
        return image_base + offset

    dynamic_entries: list[tuple[int, int]] = [
        *((1, library_offsets[library]) for library in needed_libraries),  # DT_NEEDED
        (5, _va(dynstr_offset)),  # DT_STRTAB
        (6, _va(dynsym_offset)),  # DT_SYMTAB
        (10, len(dynstr)),  # DT_STRSZ
        (11, 16),  # DT_SYMENT
    ]
    if verneed:
        dynamic_entries += [
            (0x6FFFFFF0, _va(versym_offset)),  # DT_VERSYM
            (0x6FFFFFFE, _va(verneed_offset)),  # DT_VERNEED
            (0x6FFFFFFF, len(requirement_entries)),  # DT_VERNEEDNUM
        ]
    if rel:
        dynamic_entries += [
            (23, _va(rel_offset)),  # DT_JMPREL
            (2, len(rel)),  # DT_PLTRELSZ
            (20, 17),  # DT_PLTREL: DT_REL
        ]
    dynamic_entries.append((0, 0))  # DT_NULL
    dynamic = b"".join(struct.pack("<iI", tag, value) for tag, value in dynamic_entries)

    dynamic_offset = _align(rel_offset + len(rel))
    names = (
        b"\x00.text\x00.got.plt\x00.dynstr\x00.dynsym\x00.gnu.version\x00"
        b".gnu.version_r\x00.rel.plt\x00.dynamic\x00.shstrtab\x00"
    )
    shstrtab_offset = _align(dynamic_offset + len(dynamic))
    section_header_offset = _align(shstrtab_offset + len(names))
    filesz = section_header_offset + 10 * 40

    name_offsets: dict[str, int] = {}
    for name in (
        ".text",
        ".got.plt",
        ".dynstr",
        ".dynsym",
        ".gnu.version",
        ".gnu.version_r",
        ".rel.plt",
        ".dynamic",
        ".shstrtab",
    ):
        name_offsets[name] = names.index(name.encode("ascii") + b"\x00")

    e_ident = b"\x7fELF" + b"\x01\x01\x01" + b"\x00" * 9
    header = struct.pack(
        "<16sHHIIIIIHHHHHH",
        e_ident,
        2,  # e_type: ET_EXEC
        3,  # e_machine: EM_386
        1,  # e_version
        text_va,  # e_entry
        52,  # e_phoff
        section_header_offset,  # e_shoff
        0,  # e_flags
        52,  # e_ehsize
        32,  # e_phentsize
        2,  # e_phnum: PT_LOAD + PT_DYNAMIC
        40,  # e_shentsize
        10,  # e_shnum
        9,  # e_shstrndx
    )
    load = struct.pack("<IIIIIIII", 1, 0, image_base, image_base, filesz, filesz, 7, 0x1000)
    dynamic_phdr = struct.pack(
        "<IIIIIIII",
        2,  # p_type: PT_DYNAMIC
        dynamic_offset,
        _va(dynamic_offset),
        _va(dynamic_offset),
        len(dynamic),
        len(dynamic),
        6,  # R|W
        4,
    )

    def _shdr(
        name: int,
        sh_type: int,
        flags: int,
        address: int,
        offset: int,
        size: int,
        *,
        link: int = 0,
        info: int = 0,
        alignment: int = 1,
        entsize: int = 0,
    ) -> bytes:
        return struct.pack(
            "<IIIIIIIIII",
            name,
            sh_type,
            flags,
            address,
            offset,
            size,
            link,
            info,
            alignment,
            entsize,
        )

    section_headers = b"".join(
        [
            b"\x00" * 40,  # null section
            _shdr(name_offsets[".text"], 1, 0x6, text_va, text_offset, len(code), alignment=16),
            _shdr(
                name_offsets[".got.plt"], 1, 0x3, _va(got_offset), got_offset, got_size, alignment=4
            ),
            _shdr(
                name_offsets[".dynstr"],
                3,
                0x2,
                _va(dynstr_offset),
                dynstr_offset,
                len(dynstr),
                alignment=1,
            ),
            _shdr(
                name_offsets[".dynsym"],
                11,
                0x2,
                _va(dynsym_offset),
                dynsym_offset,
                len(dynsym),
                link=3,
                info=1,
                alignment=4,
                entsize=16,
            ),
            _shdr(
                name_offsets[".gnu.version"],
                0x6FFFFFFF,
                0x2,
                _va(versym_offset),
                versym_offset,
                len(versym),
                link=4,
                alignment=2,
                entsize=2,
            ),
            _shdr(
                name_offsets[".gnu.version_r"],
                0x6FFFFFFE,
                0x2,
                _va(verneed_offset),
                verneed_offset,
                len(verneed),
                link=3,
                info=len(requirement_entries),
                alignment=4,
            ),
            _shdr(
                name_offsets[".rel.plt"],
                9,
                0x2,
                _va(rel_offset),
                rel_offset,
                len(rel),
                link=4,
                info=1,
                alignment=4,
                entsize=8,
            ),
            _shdr(
                name_offsets[".dynamic"],
                6,
                0x3,
                _va(dynamic_offset),
                dynamic_offset,
                len(dynamic),
                link=3,
                alignment=4,
                entsize=8,
            ),
            _shdr(name_offsets[".shstrtab"], 3, 0x0, 0, shstrtab_offset, len(names), alignment=1),
        ]
    )

    out = bytearray(header + load + dynamic_phdr)
    out += b"\x00" * (text_offset - len(out))
    out += code
    out += b"\x00" * (got_offset - len(out))
    out += b"\x00" * got_size
    out += b"\x00" * (dynstr_offset - len(out))
    out += dynstr
    out += b"\x00" * (dynsym_offset - len(out))
    out += dynsym
    out += b"\x00" * (versym_offset - len(out))
    out += versym
    out += b"\x00" * (verneed_offset - len(out))
    out += verneed
    out += b"\x00" * (rel_offset - len(out))
    out += rel
    out += b"\x00" * (dynamic_offset - len(out))
    out += dynamic
    out += b"\x00" * (shstrtab_offset - len(out))
    out += names
    out += b"\x00" * (section_header_offset - len(out))
    out += section_headers
    return bytes(out)


def append_pe_section(pe: bytes, name: str, data: bytes) -> bytes:
    """Append a section (*name*, *data*) to a minimal PE built by :func:`make_pe`.

    Used by tests that need a second section (e.g. a ``.rsrc`` resource
    section for ``rebrew resource``).  Appends one section header, bumps
    NumberOfSections, and places the raw data at the next file-aligned
    offset.  Returns the patched PE bytes.
    """
    lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
    n_sections = struct.unpack_from("<H", pe, lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", pe, lfanew + 20)[0]
    size_of_headers = struct.unpack_from("<I", pe, lfanew + 24 + 0x54)[0]
    file_align = struct.unpack_from("<I", pe, lfanew + 24 + 0x3C)[0]
    sec_align = struct.unpack_from("<I", pe, lfanew + 24 + 0x38)[0]
    size_of_image = struct.unpack_from("<I", pe, lfanew + 24 + 0x50)[0]

    out = bytearray(pe)
    # Section headers start right after the optional header.
    sec_table = lfanew + 24 + opt_size
    new_header_off = sec_table + n_sections * 40
    raw_off = (len(out) + file_align - 1) // file_align * file_align
    out += b"\x00" * (raw_off - len(out))

    # Raw data at raw_off; VA at the next section-aligned boundary.
    va = ((size_of_image + sec_align - 1) // sec_align) * sec_align
    out += data
    raw_size = ((len(data) + file_align - 1) // file_align) * file_align

    name_field = name.encode("ascii")[:8].ljust(8, b"\x00")
    hdr = struct.pack(
        "<8sIIIIIIHHI",
        name_field,
        len(data),  # VirtualSize
        va,  # VirtualAddress
        raw_size,  # SizeOfRawData
        raw_off,  # PointerToRawData
        0,
        0,
        0,
        0,
        0x40000040,  # INITIALIZED_DATA | READ
    )
    # Header table must fit inside the headers region.
    assert new_header_off + 40 <= size_of_headers, "section table overflow"
    out[new_header_off : new_header_off + 40] = hdr
    struct.pack_into("<H", out, lfanew + 6, n_sections + 1)
    struct.pack_into("<I", out, lfanew + 24 + 0x50, va + len(data))
    return bytes(out)
