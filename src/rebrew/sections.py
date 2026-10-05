"""sections.py - Binary section and globals helpers.

Provides section parsing from binary headers, global variable
scanning from annotated source files, and shared x86 code-analysis
utilities (back-jump detection, padding trimming).
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rebrew.config import ProjectConfig
from rebrew.sources import iter_sources as iter_sources

logger = logging.getLogger(__name__)


def trim_trailing_padding(data: bytes, padding: tuple[int, ...] | None = None) -> int:
    r"""Return the length of *data* after stripping trailing padding bytes.

    >>> trim_trailing_padding(b'\x55\x89\xe5\xcc\xcc')
    3
    >>> trim_trailing_padding(b'\xcc\xcc\xcc')
    0
    """
    if padding is None:
        from rebrew.binary_loader import PADDING_BYTES

        padding = PADDING_BYTES
    end = len(data)
    while end > 0 and data[end - 1] in padding:
        end -= 1
    return end


# ``jecxz`` / ``jcxz`` / ``jrcxz`` are relative too, and were never part of the
# out-of-line-tail check (short and near jmp/jcc only).
_NOT_A_BACK_JUMP = frozenset({"jcxz", "jecxz", "jrcxz"})


def has_back_jumps(
    data: bytes,
    func_start_off: int,
    func_end_off: int,
    base_offset: int,
) -> bool:
    """Check if *data* contains relative jumps targeting [*func_start_off*, *func_end_off*).

    *base_offset* is the address where *data* begins (a VA or a section
    offset). Capstone disassembles the bytes as x86-32 and reads each
    relative ``jmp`` / ``jcc`` target. An ``E9`` or ``70``-``7F`` byte inside
    another instruction's immediate is not a jump. Undecodable bytes are
    skipped. Used to identify out-of-line code that belongs to the
    preceding function.
    """
    if not data:
        return False
    from capstone.x86 import X86_OP_IMM

    from rebrew.analysis import capstone_for

    for insn in capstone_for().disasm(data, base_offset):
        mnemonic = insn.mnemonic
        if not mnemonic.startswith("j") or mnemonic in _NOT_A_BACK_JUMP:
            continue
        for op in insn.operands:
            if op.type == X86_OP_IMM and func_start_off <= op.imm < func_end_off:
                return True
    return False


if TYPE_CHECKING:
    from rebrew.binary_model import BinaryInfo


def sections_from_info(info: "BinaryInfo") -> dict[str, dict[str, int]]:
    """Build the section metadata dict from an already-loaded ``BinaryInfo``.

    Splits ``.data`` into ``.data`` (raw) + ``.bss`` (zero-fill tail) when
    the raw size is smaller than the virtual size, mirroring how the
    binary loader models the file.
    """
    sections: dict[str, dict[str, int]] = {}
    for name, sec in info.sections.items():
        if name == ".data" and sec.size > sec.raw_size:
            sections[".data"] = {
                "va": sec.va,
                "size": sec.raw_size,
                "fileOffset": sec.file_offset,
            }
            sections[".bss"] = {
                "va": sec.va + sec.raw_size,
                "size": sec.size - sec.raw_size,
                "fileOffset": 0,
            }
        else:
            sections[name] = {
                "va": sec.va,
                "size": sec.size,
                "fileOffset": sec.file_offset,
            }
    return sections


def get_globals(src_dir: Path, cfg: ProjectConfig | None = None) -> dict[int, dict[str, Any]]:
    """Coverage globals from the same source/header inventory as ``rebrew data list``.

    Declaration sites, storage owners and users remain distinct. Durable data
    extents override type estimates; headers and migrated metadata are included.
    """
    from rebrew.data_layout import estimate_type_size
    from rebrew.data_scan import scan_globals

    scan = scan_globals(src_dir, cfg)
    if cfg is not None:
        from rebrew.data_ownership import enrich_library_owners

        enrich_library_owners(scan, cfg)
    globals_dict: dict[int, dict[str, Any]] = {}
    entries = sorted(
        scan.globals.values(),
        key=lambda entry: (
            entry.storage_kind == "span",
            entry.storage_kind == "alias",
            not bool(entry.defined_in or entry.library_owners),
            entry.name == "unknown",
        ),
    )
    for entry in entries:
        if not entry.annotated:
            continue
        from rebrew.data_metadata import get_data_entry

        meta = (
            get_data_entry(cfg.metadata_dir, entry.va, module=entry.module)
            if cfg and getattr(cfg, "metadata_dir", None)
            else {}
        )
        row = globals_dict.setdefault(
            entry.va,
            {
                "va": entry.va,
                "name": entry.name,
                "decl": entry.declaration,
                "files": [],
                "module": entry.module,
                "size": meta.get(
                    "size", estimate_type_size(entry.type_str) if entry.type_str else 4
                ),
                "status": meta.get("status", ""),
                "defined_in": [],
                "referenced_in": [],
                "declared_in": [],
                "library_owners": [],
                "generated_owners": [],
                "storage_kind": entry.storage_kind,
                "backing": entry.backing,
            },
        )
        for key in (
            "defined_in",
            "referenced_in",
            "declared_in",
            "library_owners",
            "generated_owners",
        ):
            if entry.name != row["name"] and key in {
                "defined_in",
                "library_owners",
                "generated_owners",
            }:
                continue
            for value in getattr(entry, key):
                if value not in row[key]:
                    row[key].append(value)
        row["files"] = list(row["declared_in"])
        row["owners"] = [
            *row["defined_in"],
            *row["generated_owners"],
            *(f"{owner['library']}:{owner['member']}" for owner in row["library_owners"]),
        ]
    return globals_dict


def get_text_section_size(bin_path: Path, root: Path | None = None, target: str = "") -> int:
    """Get .text section virtual size from binary headers.

    With *root*/*target*, the committed layout package answers first
    (LIEF-free — keeps ``status``/``lint`` startup ~0.11 s lighter); LIEF
    on *bin_path* remains the fallback.
    """
    if root is not None and target:
        from rebrew.layout_meta import read_layout_header

        hdr = read_layout_header(root, target, bin_path)
        if hdr is not None:
            return int(hdr["text_size"])
    try:
        from rebrew.binary_loader import load_binary

        info = load_binary(bin_path)
        return info.text_size
    except (ImportError, OSError, KeyError, ValueError, RuntimeError) as exc:
        logger.warning("text section size unavailable for %s: %s", bin_path, exc)
        return 0
