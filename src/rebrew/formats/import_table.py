"""formats/import_table.py — Import-table parsing and import-stub detection.

Parses an import table via LIEF — a PE's DLL name → API name → IAT slot VA, or
an ELF's DT_NEEDED libraries and undefined dynamic symbols — and detects the
classic MSVC import stubs in ``.text``: ``jmp [iat]`` sequences (``FF 25``,
an absolute slot VA on PE32 and a RIP-relative displacement on PE32+).
Library layer under the ``rebrew binary imports list`` command
(:mod:`rebrew.binary.imports`) and every analysis pass that names imported APIs.
"""

from __future__ import annotations

import logging
import threading
lazy import struct
lazy from pathlib import Path
lazy from typing import Any

log = logging.getLogger(__name__)

#: Bytes of an import thunk, ``FF 25`` and its 32-bit operand: the whole stub.
IMPORT_THUNK_SIZE = 6

#: Bytes of a direct ``call rel32`` (``E8`` and its displacement).
_CALL_SIZE = 5

#: Bytes that may end the code before a stub: int3 and nop padding, ``ret``.
_STUB_PRECEDERS = frozenset({0xCC, 0x90, 0xC3})

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
    int | None, "hint_name_rva": int | None}`` records, one per imported API
    (``name`` is ``ordinal_<N>`` and ``ordinal`` is N for a PE import by ordinal), or one
    per referenced module with an empty ``name`` when a 16-bit NE carries no
    classic import table, or for an ELF's DT_NEEDED library entries, which
    precede its symbols.  ``iat_va`` is 0 for NE imports (Win16 uses
    per-segment thunks, not an IAT).  Empty list for unrecognized files or
    parse failures.

    ``hint_name_rva`` is the PE named import's hint/name entry RVA, not its
    IAT slot or the hint value. It is None for ordinal imports and non-PE
    records. Physical hint/name order does not establish linker load order.

    Memoized per ``(resolved path, mtime_ns, size, ino, ctime_ns)`` (bounded
    dict + lock, mirroring ``rebrew.formats.binary_loader.iat_slot_vas``): one
    run parses the target from the report, pe_symbols, the binary gate, the
    decompiler dossier and the toolchain detector, and each miss re-ran a full
    LIEF parse of the same multi-megabyte image.  A rebuild at the same path
    invalidates via mtime/size/inode, and change time catches an in-place
    rewrite whose mtime was restored.  The caller gets fresh dicts, so a
    consumer that annotates a record cannot poison the cache.
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
    """Identity of *binary_path* for the import memo, or None if unstattable.

    Change time is part of the identity: an in-place rewrite that restores
    the old mtime keeps the inode and size, and the cached import table would
    then describe bytes the image no longer has.
    """
    try:
        st = binary_path.stat()
    except OSError:
        return None
    return f"{binary_path.resolve()}:{st.st_mtime_ns}:{st.st_size}:{st.st_ino}:{st.st_ctime_ns}"


def _parse_imports(binary_path: Path) -> list[dict[str, Any]] | None:
    """Uncached import-table parse; see :func:`parse_imports` for the shape.

    Returns ``None`` when the image could not be parsed at all, which is not
    the same answer as an image with no imports: the toolchain detector picks
    a different, confident-looking profile from a zero-import target.  A
    failure is never memoized, so a later call in the same run retries it.
    """
    from rebrew.formats.binary_loader import is_ne, load_binary

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
                            "hint_name_rva": None,
                        }
                    )
            else:
                # Module reference with no per-API detail (many Win16 binaries
                # carry no classic import table) — still report the module so
                # the DLL set is visible.
                ne_out.append(
                    {
                        "dll": mod.module,
                        "name": "",
                        "iat_va": 0,
                        "ordinal": None,
                        "hint_name_rva": None,
                    }
                )
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
                        "hint_name_rva": None if fn.is_ordinal else int(fn.data),
                    }
                )
    except Exception as exc:  # LIEF raises on a malformed image
        # Mid-table: the records collected so far are real, but the IAT is
        # truncated.  Returning them as a complete table makes the toolchain
        # detector trust a partial import set, and parse_imports would then
        # memoize that partial answer as a successful parse.  Fail the whole
        # read so callers degrade to "unknown" and a later call retries.
        log.warning(
            "PE import enumeration of %s failed after %d record(s): %s: %s",
            binary_path,
            len(out),
            type(exc).__name__,
            exc,
        )
        return None
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
        {"dll": library, "name": "", "iat_va": 0, "ordinal": None, "hint_name_rva": None}
        for library in libraries
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
                "hint_name_rva": None,
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
    """``{stub_va: api_name}`` for the import stubs :func:`find_import_stub_slots` finds."""
    table = parse_import_table(binary_path)
    return {va: table[slot] for va, slot in find_import_stub_slots(binary_path).items()}


def find_import_stub_slots(binary_path: Path) -> dict[int, int]:
    """Detect ``jmp [iat]`` import stubs in ``.text``.

    Returns ``{stub_va: iat_va}`` for every ``FF 25`` sequence whose target
    resolves to an import-table slot and that stands alone as a stub: it opens
    the section, follows a padding (``CC``/``90``) or ``ret`` (``C3``) byte, is
    the target of a direct ``call`` (``E8 rel32``) in the section, or sits
    next to another stub.  These stubs are what the linker generates for each
    imported API, so the VA maps 1:1 to an import.  A ``jmp [slot]`` that only
    follows other code is a tail call inside a function (MSVC's getSystemCP
    ends two branches with ``jmp [GetOEMCP]`` and ``jmp [GetACP]``), not a
    stub.  The test reads bytes, not decoded instructions: a stub after an
    instruction that happens to end in one of those bytes counts as a stub.

    The operand is 32 bits either way but means different things: a PE32 stub
    carries the slot's absolute VA (``jmp dword ptr [iat_va]``), a PE32+ stub a
    RIP-relative displacement (``jmp qword ptr [rip + disp32]``, resolved from
    the address of the following instruction).  A PE32+ read as absolute finds
    nothing, which is how x64 images silently reported zero stubs.

    The slot, not the name, identifies the import: every import by ordinal
    is named ``ordinal_<N>``, so ordinal N of two DLLs shares one name.
    """
    table = parse_import_table(binary_path)
    if not table:
        return {}
    from rebrew.formats.binary_loader import load_binary

    try:
        info = load_binary(binary_path)
    except OSError, KeyError, ValueError:
        return {}
    if info.format == "elf":
        return _find_elf_import_stub_slots(binary_path, info, table)
    text = info.sections.get(".text")
    if text is None or text.file_offset < 0 or text.size <= 0:
        return {}
    rip_relative = info.pointer_size == 8
    stub_va = text.va
    blob = info.data[text.file_offset : text.file_offset + text.size]
    stubs: dict[int, int] = {}
    pos = 0
    while (i := blob.find(b"\xff\x25", pos, max(0, len(blob) - 4))) != -1:
        pos = i + 1
        # ``<i`` reads the operand signed (a RIP-relative disp32 is signed).
        # A PE32 operand is the slot's absolute VA, so an image based at or
        # above 0x80000000 decodes negative and misses the table; mask it back
        # to 32 bits rather than look up a negative key.
        operand = struct.unpack_from("<i", blob, i + 2)[0]
        target = (
            (stub_va + i + IMPORT_THUNK_SIZE + operand) & 0xFFFFFFFFFFFFFFFF
            if rip_relative
            else operand & 0xFFFFFFFF
        )
        if target in table:
            stubs[stub_va + i] = target
    if not stubs:
        return {}
    called: set[int] = set()
    pos = 0
    while (i := blob.find(b"\xe8", pos, max(0, len(blob) - 4))) != -1:
        pos = i + 1
        callee = stub_va + i + _CALL_SIZE + struct.unpack_from("<i", blob, i + 1)[0]
        if callee in stubs:
            called.add(callee)
    alone = {
        va
        for va in stubs
        if va == stub_va or va in called or blob[va - stub_va - 1] in _STUB_PRECEDERS
    }
    # Grow through runs: a stub beside a stub is one.
    pending = list(alone)
    while pending:
        va = pending.pop()
        for neighbour in (va - IMPORT_THUNK_SIZE, va + IMPORT_THUNK_SIZE):
            if neighbour in stubs and neighbour not in alone:
                alone.add(neighbour)
                pending.append(neighbour)
    return {va: slot for va, slot in stubs.items() if va in alone}


def _elf_gp_value(binary_path: Path, info: Any) -> int | None:
    """Resolve the ELF ``$gp`` base for MIPS stub GOT offsets, if available."""
    import lief

    try:
        elf = lief.ELF.parse(str(binary_path))
    except Exception:
        return None
    if elf is None:
        return None
    for entry in list(getattr(elf, "dynamic_entries", None) or []):
        if entry.tag == lief.ELF.DynamicEntry.TAG.MIPS_GP_VALUE:
            return int(entry.value)
    got_sec = info.sections.get(".got")
    if got_sec is not None:
        return int(got_sec.va) + 0x7FF0
    return None


def _disasm_x86_plt_stubs(
    info: Any,
    blob: bytes,
    sec_va: int,
    valid_slots: set[int],
    got_base: int | None,
) -> dict[int, int]:
    """Disassemble an x86/x86-64 PLT section and resolve ``jmp``/``bnd jmp`` GOT slots."""
    import capstone
    from capstone.x86 import X86_INS_JMP, X86_OP_MEM, X86_REG_EBX, X86_REG_RIP

    from rebrew.formats.binary_loader import capstone_config_for

    if info.arch:
        cs_arch, cs_mode = capstone_config_for(info)
    else:
        cs_arch = capstone.CS_ARCH_X86
        cs_mode = capstone.CS_MODE_64 if info.pointer_size == 8 else capstone.CS_MODE_32
    cs = capstone.Cs(cs_arch, cs_mode)
    cs.detail = True
    stubs: dict[int, int] = {}
    endbr_va: int | None = None
    endbr_end = 0
    for insn in cs.disasm(blob, sec_va):
        if insn.mnemonic in ("endbr64", "endbr32"):
            endbr_va = insn.address
            endbr_end = insn.address + insn.size
            continue
        if (
            insn.id == X86_INS_JMP
            and len(insn.operands) == 1
            and insn.operands[0].type == X86_OP_MEM
        ):
            mem = insn.operands[0].mem
            target: int | None = None
            if mem.base == X86_REG_RIP:
                target = (insn.address + insn.size + mem.disp) & 0xFFFFFFFFFFFFFFFF
            elif mem.base == 0 and mem.index == 0:
                target = mem.disp & 0xFFFFFFFF
            elif mem.base == X86_REG_EBX and got_base is not None:
                target = (got_base + mem.disp) & 0xFFFFFFFF
            if target is not None and target in valid_slots:
                stub_va = (
                    endbr_va if endbr_va is not None and endbr_end == insn.address else insn.address
                )
                stubs[stub_va] = target
        endbr_va = None
    return stubs


def _disasm_mips_plt_stubs(
    binary_path: Path,
    info: Any,
    blob: bytes,
    sec_va: int,
    valid_slots: set[int],
) -> dict[int, int]:
    """Disassemble a MIPS ``.MIPS.stubs`` / ``.plt`` section for GOT slot targets."""
    import capstone
    from capstone.mips import (
        MIPS_INS_ADDIU,
        MIPS_INS_JALR,
        MIPS_INS_JR,
        MIPS_INS_LUI,
        MIPS_INS_LW,
        MIPS_OP_IMM,
        MIPS_OP_MEM,
        MIPS_OP_REG,
        MIPS_REG_GP,
    )

    from rebrew.formats.binary_loader import capstone_config_for

    cs_arch, cs_mode = capstone_config_for(info)
    cs = capstone.Cs(cs_arch, cs_mode)
    cs.detail = True
    gp_val = _elf_gp_value(binary_path, info)
    stubs: dict[int, int] = {}
    hi_regs: dict[int, tuple[int, int]] = {}
    for insn in cs.disasm(blob, sec_va):
        if insn.id == MIPS_INS_LUI and len(insn.operands) == 2:
            dst, imm_op = insn.operands
            if dst.type == MIPS_OP_REG and imm_op.type == MIPS_OP_IMM:
                hi_regs[dst.reg] = (insn.address, (imm_op.imm & 0xFFFF) << 16)
        elif insn.id == MIPS_INS_LW and len(insn.operands) == 2:
            mem_op = insn.operands[1]
            if mem_op.type == MIPS_OP_MEM:
                base = mem_op.mem.base
                disp = mem_op.mem.disp
                if base in hi_regs:
                    lui_va, hi_val = hi_regs[base]
                    candidate = (hi_val + disp) & 0xFFFFFFFF
                    if candidate in valid_slots:
                        stubs[lui_va] = candidate
                elif base == MIPS_REG_GP and gp_val is not None:
                    candidate = (gp_val + disp) & 0xFFFFFFFF
                    if candidate in valid_slots:
                        stubs[insn.address] = candidate
        elif insn.id == MIPS_INS_ADDIU and len(insn.operands) == 3:
            _dst, src, imm_op = insn.operands
            if src.type == MIPS_OP_REG and imm_op.type == MIPS_OP_IMM and src.reg in hi_regs:
                lui_va, hi_val = hi_regs[src.reg]
                candidate = (hi_val + imm_op.imm) & 0xFFFFFFFF
                if candidate in valid_slots:
                    stubs[lui_va] = candidate
        elif insn.id in (MIPS_INS_JR, MIPS_INS_JALR):
            hi_regs.clear()
    return stubs


def _find_elf_import_stub_slots(
    binary_path: Path, info: Any, table: dict[int, str]
) -> dict[int, int]:
    """Detect ELF PLT/MIPS import stubs ``{stub_va: got_slot_va}``."""
    valid_slots = {slot for slot, name in table.items() if name}
    if not valid_slots:
        return {}
    got_sec = info.sections.get(".got.plt") or info.sections.get(".got")
    got_base = got_sec.va if got_sec is not None else None
    arch = str(getattr(info, "arch", "") or "")
    stubs: dict[int, int] = {}

    for sec_name in (".plt.sec", ".plt", ".plt.got", ".MIPS.stubs"):
        sec = info.sections.get(sec_name)
        if sec is None or sec.file_offset < 0 or sec.raw_size <= 0:
            continue
        blob = info.data[sec.file_offset : sec.file_offset + sec.raw_size]
        if not blob:
            continue
        if arch in ("", "x86_32", "x86_64"):
            stubs.update(_disasm_x86_plt_stubs(info, blob, sec.va, valid_slots, got_base))
        elif arch.startswith("mips"):
            stubs.update(_disasm_mips_plt_stubs(binary_path, info, blob, sec.va, valid_slots))

    import lief

    try:
        elf = lief.ELF.parse(str(binary_path))
    except Exception:
        elf = None
    if elf is None:
        return stubs

    pltgot = [
        r
        for r in (getattr(elf, "pltgot_relocations", None) or [])
        if getattr(r, "has_symbol", False) and int(r.address) in valid_slots
    ]
    if not pltgot:
        return stubs

    mapped_slots = set(stubs.values())
    if ".plt.sec" in info.sections:
        sec = info.sections[".plt.sec"]
        if sec.file_offset >= 0 and sec.raw_size >= len(pltgot) * 16:
            for idx, reloc in enumerate(pltgot):
                slot = int(reloc.address)
                if slot not in mapped_slots:
                    stubs.setdefault(sec.va + idx * 16, slot)
    elif ".plt" in info.sections:
        sec = info.sections[".plt"]
        hdr_size, entry_size = (
            (20, 12) if arch == "arm32" else (32, 16) if arch == "arm64" else (16, 16)
        )
        if sec.file_offset >= 0 and sec.raw_size >= hdr_size + len(pltgot) * entry_size:
            for idx, reloc in enumerate(pltgot):
                slot = int(reloc.address)
                if slot not in mapped_slots:
                    stubs.setdefault(sec.va + hdr_size + idx * entry_size, slot)
    elif ".MIPS.stubs" in info.sections:
        sec = info.sections[".MIPS.stubs"]
        if sec.file_offset >= 0 and sec.raw_size >= len(pltgot) * 16:
            for idx, reloc in enumerate(pltgot):
                slot = int(reloc.address)
                if slot not in mapped_slots:
                    stubs.setdefault(sec.va + idx * 16, slot)
    return stubs
