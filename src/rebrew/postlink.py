"""postlink.py — post-link layout normalization for byte-identical builds.

The MSVC6 linker (and most linkers) is not a source-order-preserving
assembler for every section: the IAT slot order, the import hint/name record
placement, and the ``.data`` COMDAT order are all determined by the linker's
internal hash-driven processing, so a recompiled binary whose *content* is
correct can still differ from the reference in *placement*.  This module
provides a small fixer framework that converges a built DLL/EXE onto the
reference's layout, byte-for-byte, without re-linking:

* ``imports`` — verify the import set matches, rewrite ``.text`` IAT slot
  operands, and copy the reference's import bookkeeping (IAT arrays,
  descriptors, OFT arrays, hint/name records, DLL names) verbatim.  Valid
  because for an identical import set every byte of that region is derived
  from the import set — only its order is linker-determined.
* ``data`` — rewrite ``.text`` absolute data operands and E8/E9 call/jump
  targets to the reference's values (the code is position-aligned, so at each
  position the operand is the only difference), grow ``.data`` to the
  reference's raw size and copy it, replace ``.reloc``, and trim the extra
  ``.text`` tail (import thunks/stubs the original build dead-stripped).
* ``pe-metadata`` — normalize toolchain-stamped PE metadata: DOS stub /
  ``e_lfanew``, ``TimeDateStamp``, ``.data`` VirtualSize (BSS tail),
  ``.reloc`` VA, ``SizeOfImage``, export ``Characteristics``, and CheckSum.

The reference is supplied as **text-only layout metadata** (see
``rebrew.layout_meta`` — the ``layout/<target>/`` package written by
``rebrew gen-layout``), never as a binary snapshot or the original DLL, so
the fixers run on a public checkout with zero binary blobs at rest.  A raw
reference binary may still be passed directly for development/tests; it is
reduced to the same metadata in memory.

Architecture notes:

- Each fixer operates on the raw file bytes (``bytearray``) so the output is
  byte-identical; LIEF is used only for parsing the *built* binary (imports,
  sections, data directories).  ``lief.PE.Binary.write()`` re-serializes and
  would change bytes, so header fields are patched at their computed offsets
  instead.
- Fixers run in dependency order: ``imports`` → ``data`` → ``pe-metadata``
  (the operand rewrites assume the import bookkeeping is already converged).
- ``data`` and ``pe-metadata`` assume the built ``.text`` is position-aligned
  with the reference (functions at the same VAs) — the normal state for a
  decompilation that has passed ``rebrew test``.

Usage:
    rebrew postlink <built.dll> [<reference.dll> | --layout layout/<target>]
                   [--fix imports|data|pe-metadata|all]
"""

from __future__ import annotations

import dataclasses
import struct
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import lief
import typer
from rich.console import Console

from rebrew.binary_loader import BinaryInfo, load_binary
from rebrew.cli import EXIT_ERROR, error_exit, json_print
from rebrew.layout_meta import ImportMeta, LayoutMetadata, extract_layout, load_package
from rebrew.utils import atomic_write_bytes

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Fixer protocol
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class FixerReport:
    """Outcome of one post-link fixer run."""

    name: str
    changed: bool
    messages: list[str] = dataclasses.field(default_factory=list)
    stats: dict[str, int] = dataclasses.field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Plain dict for ``--json`` output."""
        return {
            "fixer": self.name,
            "changed": self.changed,
            "messages": self.messages,
            "stats": self.stats,
        }


Fixer = Callable[[bytearray, LayoutMetadata, BinaryInfo], FixerReport]


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _pe(raw: bytes) -> lief.PE.Binary:
    """Parse *raw* with LIEF, raising a clear error for non-PE input."""
    binary = lief.PE.parse(raw)
    if binary is None:
        raise ValueError("not a PE binary")
    return binary


def _rva_to_offset(info: BinaryInfo, rva: int) -> int:
    """Map an image RVA (e.g. ``0x24000``) to its file offset."""
    for section in info.sections.values():
        va = section.va - info.image_base
        if va <= rva < va + max(section.size, section.raw_size):
            return section.file_offset + (rva - va)
    raise ValueError(f"rva 0x{rva:x} not in any section")


def _section_table(info: BinaryInfo) -> tuple[int, int, int]:
    """Return (e_lfanew, optional-header offset, section-table offset)."""
    e = struct.unpack_from("<I", info.data, 0x3C)[0]
    if info.data[e : e + 4] != b"PE\x00\x00":
        raise ValueError("not a PE binary (bad e_lfanew)")
    coff = e + 4
    opt_size = struct.unpack_from("<H", info.data, coff + 16)[0]
    return e, coff + 20, coff + 20 + opt_size


def _section_header_offset(info: BinaryInfo, name: str) -> int:
    """File offset of the section-table entry for *name*."""
    _, _, sec_off = _section_table(info)
    e = struct.unpack_from("<I", info.data, 0x3C)[0]
    n = struct.unpack_from("<H", info.data, e + 4 + 2)[0]
    for i in range(n):
        h = sec_off + 40 * i
        sn = info.data[h : h + 8].rstrip(b"\x00").decode(errors="replace")
        if sn == name:
            return h
    raise ValueError(f"section {name!r} not found")


# ---------------------------------------------------------------------------
# Fixer 1: imports
# ---------------------------------------------------------------------------


def _entry_key(dll: str | bytes, name: str | bytes | None, ordinal: int | None) -> tuple[str, str]:
    """Canonical import key: ``(dll, name)`` or ``(dll, "#<ordinal>")`` for ordinal-only.

    LIEF reports ordinal-only imports (WS2_32) with an *empty* name string —
    falsy names are treated as ordinals, matching the metadata (name=None).
    """
    return (str(dll), str(name) if name else f"#{ordinal}")


def _import_signature(meta_imports: Iterable[ImportMeta]) -> list[tuple[str, list[str]]]:
    """Import set from the metadata as ``[(dll, sorted [entry names or ordinals])]``.

    Entries are *sorted* so the signature is order-insensitive: the MSVC6
    linker assigns IAT slots in a hash-driven order that differs between
    builds, and the whole point of the imports fixer is to converge that
    order — comparing it here would make the fixer refuse the exact case it
    repairs.
    """
    sig: list[tuple[str, list[str]]] = []
    per_dll: dict[str, list[str]] = {}
    for imp in meta_imports:
        key = imp.name if imp.name else f"#{imp.ordinal}"
        per_dll.setdefault(imp.dll, []).append(key)
    for dll, names in per_dll.items():
        sig.append((dll, sorted(names)))
    return sig


def _built_import_signature(raw: bytes) -> list[tuple[str, list[str]]]:
    pe = _pe(raw)
    sig: list[tuple[str, list[str]]] = []
    for imp in pe.imports:
        names = sorted(str(e.name) if e.name else f"#{e.ordinal}" for e in imp.entries)
        sig.append((str(imp.name), names))
    return sig


def _fix_imports(built: bytearray, meta: LayoutMetadata, info_b: BinaryInfo) -> FixerReport:
    """Converge the built import layer onto the reference's.

    For an identical import set the IAT arrays, import descriptors, OFT
    arrays, hint/name records and DLL-name strings contain exactly the same
    bytes as the reference's — the MSVC6 linker just places the records in a
    hash-driven order and may assign IAT slots in a different order.  We
    rewrite the ``.text`` operands that point at moved slots and copy the two
    regions verbatim (from the text metadata).
    """
    report = FixerReport(name="imports", changed=False)
    sig_b = _built_import_signature(bytes(built))
    sig_r = _import_signature(meta.imports)
    if sig_b != sig_r:
        _entry_diff = {}
        for _d in sorted({d for d, _ in sig_b} | {d for d, _ in sig_r}):
            _eb = dict(sig_b).get(_d, [])
            _er = dict(sig_r).get(_d, [])
            _only_b = sorted(set(_eb) - set(_er))
            _only_r = sorted(set(_er) - set(_eb))
            if _only_b or _only_r:
                _entry_diff[_d] = (f"built-only={_only_b}", f"ref-only={_only_r}")
        raise ValueError(
            f"import sets differ — refusing to copy bookkeeping (entries={_entry_diff})"
        )

    pe_b = _pe(bytes(built))

    def data_dir(pe: lief.PE.Binary, kind: lief.PE.DataDirectory.TYPES) -> tuple[int, int]:
        for d in pe.data_directories:
            if d.type == kind:
                return d.rva, d.size
        return 0, 0

    iat_rva, iat_size = data_dir(pe_b, lief.PE.DataDirectory.TYPES.IAT)
    imp_rva, _ = data_dir(pe_b, lief.PE.DataDirectory.TYPES.IMPORT_TABLE)

    # ---- 1. rewrite .text operands that reference moved IAT slots ----
    # built slot VAs come from the built binary (LIEF); reference slot VAs
    # from the metadata.  Only slots that differ are remapped.
    slots_b: dict[tuple[str, str], int] = {}
    for imp_b in pe_b.imports:
        for e in imp_b.entries:
            slots_b[_entry_key(imp_b.name, e.name, e.ordinal)] = e.iat_address
    slots_r: dict[tuple[str, str], int] = {}
    for imp_m in meta.imports:
        slots_r[_entry_key(imp_m.dll, imp_m.name, imp_m.ordinal)] = imp_m.iat_va
    remap = {slots_b[k]: slots_r[k] for k in slots_b if slots_b[k] != slots_r[k]}
    if remap and iat_rva:
        text = info_b.sections[".text"]
        moved = 0
        for off in range(text.file_offset, text.file_offset + text.raw_size - 4):
            v = struct.unpack_from("<I", built, off)[0]
            slot = v - info_b.image_base
            if slot in remap:
                struct.pack_into("<I", built, off, remap[slot] + info_b.image_base)
                moved += 1
        report.stats["slot_operands_rewritten"] = moved
        report.changed = report.changed or moved > 0

    # ---- 2. safety: the .rdata prefix must already match ----
    # The hint/name records and OFT arrays are derived from the content before
    # the import directory; if that prefix drifted the copy would be wrong.
    if meta.prefix:
        prefix_lo = _rva_to_offset(info_b, iat_rva + iat_size)
        prefix_hi = _rva_to_offset(info_b, imp_rva)
        if prefix_hi - prefix_lo != len(meta.prefix):
            raise ValueError(
                "built .rdata prefix size does not match the reference — "
                "check the debug directory: builds with /debug carry an extra "
                "0x1c-byte directory that shifts everything"
            )
        if bytes(built[prefix_lo:prefix_hi]) != meta.prefix:
            raise ValueError(
                "built .rdata prefix between the IAT and the import directory "
                "does not match the reference — refusing to copy the import "
                "bookkeeping (check the debug directory: builds with /debug "
                "carry an extra 0x1c-byte directory that shifts everything)"
            )

    # ---- 3. copy the IAT arrays + the import bookkeeping verbatim ----
    if meta.iat:
        lo = _rva_to_offset(info_b, iat_rva)
        built[lo : lo + len(meta.iat)] = meta.iat
    if meta.bookkeeping:
        lo = _rva_to_offset(info_b, imp_rva)
        if lo + len(meta.bookkeeping) > len(built):
            built.extend(b"\x00" * (lo + len(meta.bookkeeping) - len(built)))
        built[lo : lo + len(meta.bookkeeping)] = meta.bookkeeping
    report.changed = True
    report.messages.append(
        f"copied IAT ({len(meta.iat):#x} bytes) and bookkeeping ({len(meta.bookkeeping):#x} bytes)"
    )
    return report


# ---------------------------------------------------------------------------
# Fixer 2: data / reloc
# ---------------------------------------------------------------------------


def _fix_data(built: bytearray, meta: LayoutMetadata, info_b: BinaryInfo) -> FixerReport:
    """Converge ``.data``/``.reloc`` and the ``.text`` data operands.

    The linker's ``.data`` COMDAT order is hash-driven (not source-orderable),
    so once the content is correct the raw ``.data`` is copied from the
    reference.  The ``.text`` operand rewrite covers absolute pointers into
    ``.rdata``/``.data`` (the full VirtualSize, including the BSS tail beyond
    the raw size) and E8/E9 relative call/jump targets.  All reference bytes
    come from the text metadata (operands/calls sparse maps + hex dumps).
    """
    report = FixerReport(name="data", changed=False)
    text = info_b.sections[".text"]
    rdata = meta.section(".rdata")
    data_m = meta.section(".data")

    # operand ranges, image-base-relative (== the reference's RVA space)
    lo_r = rdata.va
    hi_r = rdata.va + rdata.vs
    lo_d = data_m.va
    hi_d = data_m.va + data_m.vs

    def in_range(rva: int) -> bool:
        return lo_r <= rva < hi_r or lo_d <= rva < hi_d

    # ---- 1. absolute data operands (sparse map: every position where the
    # reference holds an image-relative address; only differing positions are
    # rewritten) ----
    operands = 0
    for off_rel, val in meta.operands.items():
        off = text.file_offset + off_rel
        if struct.unpack_from("<I", built, off)[0] != val and in_range(
            struct.unpack_from("<I", built, off)[0] - info_b.image_base
        ):
            struct.pack_into("<I", built, off, val)
            operands += 1
    report.stats["data_operands"] = operands
    report.changed = report.changed or operands > 0

    # ---- 2. E8/E9 relative call/jump targets (context-matched via the map) ----
    rel32 = 0
    for off_rel, (val, pre, suf) in meta.calls.items():
        off = text.file_offset + off_rel
        if struct.unpack_from("<I", built, off)[0] == val:
            continue
        if (
            built[off - 1] in (0xE8, 0xE9)
            and bytes(built[off - 3 : off - 1]) == pre.to_bytes(2, "big")
            and bytes(built[off + 4 : off + 6]) == suf.to_bytes(2, "big")
        ):
            struct.pack_into("<I", built, off, val)
            rel32 += 1
    report.stats["call_targets"] = rel32
    report.changed = report.changed or rel32 > 0

    # ---- 3. trim the extra .text tail + fix .text VirtualSize ----
    # The reference's own padding beyond VirtualSize (real linkers emit INT3
    # 0xCC in the .text tail — cpubench: vs 0x29d11 < raw 0x29e00) is part
    # of the reference and must be preserved: `postlink X X` reproduces X
    # byte-for-byte.  Only bytes BEYOND the reference's raw extent are
    # trimmed.  (The fixer deliberately carries no reference .text bytes —
    # operands/calls are sparse maps — so the reference's tail region is
    # left as the built binary's, which for X X is the reference itself.)
    text_m = meta.section(".text")
    ref_raw_end = text_m.raw_ptr + text_m.raw
    if ref_raw_end < text.file_offset + text.raw_size:
        built[ref_raw_end : text.file_offset + text.raw_size] = b"\x00" * (
            text.file_offset + text.raw_size - ref_raw_end
        )
        struct.pack_into("<I", built, _section_header_offset(info_b, ".text") + 16, text_m.raw)
        struct.pack_into("<I", built, _section_header_offset(info_b, ".text") + 8, text_m.vs)
        report.changed = True

    # ---- 4. grow .data to the reference raw size and copy it ----
    data_b = info_b.sections[".data"]
    if len(meta.data) > len(built) - data_b.file_offset:
        built.extend(b"\x00" * (data_b.file_offset + len(meta.data) - len(built)))
    built[data_b.file_offset : data_b.file_offset + len(meta.data)] = meta.data
    struct.pack_into("<I", built, _section_header_offset(info_b, ".data") + 16, len(meta.data))

    # ---- 5. replace .reloc (at the reference's file offset) ----
    reloc_b = info_b.sections[".reloc"]
    reloc_m = meta.section(".reloc")
    new_rptr = reloc_m.raw_ptr
    reloc_raw = meta.reloc + b"\x00" * max(0, reloc_m.raw - len(meta.reloc))
    if new_rptr + len(reloc_raw) > len(built):
        built.extend(b"\x00" * (new_rptr + len(reloc_raw) - len(built)))
    built[new_rptr : new_rptr + len(reloc_raw)] = reloc_raw
    h = _section_header_offset(info_b, ".reloc")
    struct.pack_into("<I", built, h + 8, reloc_m.vs)  # VirtualSize
    struct.pack_into("<I", built, h + 16, len(reloc_raw))
    struct.pack_into("<I", built, h + 20, new_rptr)
    # .reloc data directory size
    e, opt, _ = _section_table(info_b)
    dd = opt + 96
    for i in range(16):
        rva = struct.unpack_from("<I", built, dd + 8 * i)[0]
        if rva == reloc_b.va - info_b.image_base:
            struct.pack_into("<I", built, dd + 8 * i + 4, reloc_m.vs)
            break
    report.changed = True
    report.messages.append(
        f".data -> {len(meta.data):#x} bytes; .reloc -> {len(reloc_raw):#x} bytes at {new_rptr:#x}"
    )
    return report


# ---------------------------------------------------------------------------
# Fixer 3: PE metadata
# ---------------------------------------------------------------------------


def _fix_pe_metadata(built: bytearray, meta: LayoutMetadata, info_b: BinaryInfo) -> FixerReport:
    """Normalize toolchain-stamped PE metadata against the reference.

    The MSVC6 link step stamps the DOS stub (Rich header / different
    ``e_lfanew``), ``TimeDateStamp``, an empty CheckSum, a too-small ``.data``
    VirtualSize (BSS placeholders are emitted as ``char[1]``), and a
    ``.reloc`` VA that predates the BSS growth.  None of these are decomp
    content; this fixer copies the reference's header/stub values from the
    metadata.
    """
    report = FixerReport(name="pe-metadata", changed=False)
    b = built
    header = meta.header
    e_r = struct.unpack_from("<I", header, 0x3C)[0]  # reference e_lfanew

    e_b, opt_b, _ = _section_table(info_b)

    # ---- 1. DOS stub + e_lfanew (header block is relocated losslessly) ----
    if e_b != e_r or b[:e_r] != header[:e_r]:
        coff = e_b + 4
        n = struct.unpack_from("<H", b, coff + 2)[0]
        opt_size = struct.unpack_from("<H", b, coff + 16)[0]
        hdr_size = 4 + 20 + opt_size + n * 40
        if e_r + hdr_size > 0x1000:
            raise ValueError("headers would overlap the first section")
        new = bytearray()
        new += header[:e_r]  # reference DOS stub (carries e_lfanew = e_r)
        new += b[e_b : e_b + hdr_size]
        new += b"\x00" * (0x1000 - len(new))
        new += b[0x1000:]
        b[:] = new
        report.changed = True
        # e_lfanew changed — recompute the header offsets before step 2
        e_b = struct.unpack_from("<I", b, 0x3C)[0]
        opt_b = e_b + 24

    # ---- 2. copy the reference's full header block ----
    # COFF Characteristics, SizeOfInitializedData, BaseOfData, SizeOfImage,
    # TimeDateStamp, CheckSum and the section table are all linker-stamped.
    # If the section layout already converged (same names + RVAs), every one
    # of those fields is derivable from the reference and can be copied
    # verbatim — recomputing any of them would never match a reference whose
    # .text still differs.
    n_b = struct.unpack_from("<H", b, e_b + 4 + 2)[0]
    opt_size_b = struct.unpack_from("<H", b, e_b + 4 + 16)[0]

    def names_at(raw: bytes | bytearray, e: int, n: int, opt_size: int) -> list[str]:
        sec_off = e + 4 + 20 + opt_size
        return [
            raw[sec_off + 40 * i : sec_off + 40 * i + 8].rstrip(b"\x00").decode(errors="replace")
            for i in range(n)
        ]

    meta_names = [s.name for s in meta.sections]
    opt_size_r = struct.unpack_from("<H", header, e_r + 4 + 16)[0]
    hdr_size_r = 4 + 20 + opt_size_r + len(meta.sections) * 40  # bytes after e_r
    if n_b == len(meta.sections) and names_at(b, e_b, n_b, opt_size_b) == meta_names:
        b[e_b : e_b + hdr_size_r] = header[e_r : e_r + hdr_size_r]
        report.changed = True
    else:
        # Section layout not converged — fall back to stamping only the
        # fields that are safe regardless of layout.
        ts = struct.unpack_from("<I", header, e_r + 4 + 4)[0]
        if struct.unpack_from("<I", b, e_b + 4 + 4)[0] != ts:
            struct.pack_into("<I", b, e_b + 4 + 4, ts)
            report.changed = True
        cs_r = struct.unpack_from("<I", header, e_r + 24 + 64)[0]
        if struct.unpack_from("<I", b, opt_b + 64)[0] != cs_r:
            struct.pack_into("<I", b, opt_b + 64, cs_r)
            report.changed = True

    # ---- 3. copy the export-dir stamp pair ----
    # LINK writes the link time into the export directory's TimeDateStamp
    # (and Characteristics); the original carries its own values.  Copy the
    # 8-byte Characteristics+TimeDateStamp pair verbatim.
    if meta.exp_rva:
        try:
            eo_b = _rva_to_offset(info_b, meta.exp_rva)
        except ValueError:
            eo_b = None
        if eo_b is not None:
            stamp = struct.pack("<II", *meta.export_stamp)
            if b[eo_b : eo_b + 8] != stamp:
                b[eo_b : eo_b + 8] = stamp
                report.changed = True

    report.messages.append("normalized DOS stub, timestamp, VS, VA, SizeOfImage, checksum")
    return report


# ---------------------------------------------------------------------------
# Fixer registry + runner
# ---------------------------------------------------------------------------

FIXERS: dict[str, Fixer] = {
    "imports": _fix_imports,
    "data": _fix_data,
    "pe-metadata": _fix_pe_metadata,
}

FIXER_ORDER: tuple[str, ...] = ("imports", "data", "pe-metadata")


def run_fixers(
    built_path: Path,
    reference_path: Path | None = None,
    fixer_names: Iterable[str] | None = None,
    layout_dir: Path | None = None,
) -> tuple[bytes, list[FixerReport]]:
    """Apply the named fixers (default: all) to *built_path*.

    The reference is the text layout package in *layout_dir* (preferred —
    zero binary bytes at rest) or a raw reference binary at *reference_path*
    (reduced to the same metadata in memory; useful for development/tests).

    Returns the patched bytes and the per-fixer reports.  Raises ``ValueError``
    if a fixer's preconditions are not met (import set mismatch, drifted
    prefix, etc.).
    """
    if layout_dir is not None:
        meta = load_package(layout_dir)
    elif reference_path is not None:
        meta = extract_layout(reference_path.read_bytes())
    else:
        raise ValueError("reference binary or --layout is required")

    info_b = load_binary(built_path)
    built = bytearray(info_b.data)

    names = list(fixer_names) if fixer_names else list(FIXER_ORDER)
    unknown = [n for n in names if n not in FIXERS]
    if unknown:
        raise ValueError(f"unknown fixers: {', '.join(unknown)}")
    names = [n for n in FIXER_ORDER if n in names]  # dependency order

    reports: list[FixerReport] = []
    for name in names:
        before = bytes(built)
        report = FIXERS[name](built, meta, info_b)
        report.changed = before != bytes(built)  # byte-diff is authoritative
        reports.append(report)
    return bytes(built), reports


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Normalize a built binary's layout onto a reference (post-link fixes).",
    rich_markup_mode="rich",
)

_FIX_CHOICES = ("all",) + FIXER_ORDER


@app.callback(invoke_without_command=True)
def main(
    built: Path = typer.Argument(..., help="Built binary to fix (in place)"),
    reference: Path | None = typer.Argument(
        None,
        help="Reference binary to converge onto (omit when --layout is used; "
        "reduced to text metadata in memory)",
    ),
    layout: Path | None = typer.Option(
        None,
        "--layout",
        help="Text-only layout package directory (layout/<target>/) from "
        "'rebrew gen-layout' — reconstruct the reference from metadata instead "
        "of a reference binary",
    ),
    fix: str = typer.Option(
        "all",
        "--fix",
        help="Fixer to run: all, imports, data, pe-metadata (defaults to all)",
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the result here instead of in place"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Converge the layout of *built* onto *reference* (byte-identical).

    Run after linking, when the decompiled content is correct but the
    linker's placement (import records, .data COMDATs, PE stamps) differs
    from the original build.  See ``rebrew postlink --help`` and
    ``docs/POSTLINK.md`` for what each fixer touches.

    The reference comes from ``--layout`` (a text-only layout package — no
    original binary or binary blobs needed) or a reference DLL directly.
    """
    if not built.exists():
        error_exit(f"built binary not found: {built}", json_mode=json_output, code=EXIT_ERROR)
    if layout is not None:
        if not layout.exists() or not layout.is_dir():
            error_exit(
                f"layout package not found: {layout} (expected layout/<target>/ "
                "with header.hex, data.hex, ... — run 'rebrew gen-layout')",
                json_mode=json_output,
                code=EXIT_ERROR,
            )
    elif reference is None:
        error_exit(
            "reference binary or --layout is required", json_mode=json_output, code=EXIT_ERROR
        )
    elif not reference.exists():
        error_exit(
            f"reference binary not found: {reference}", json_mode=json_output, code=EXIT_ERROR
        )

    fixers = [f.strip() for f in fix.split(",") if f.strip()]
    if "all" in fixers:
        fixers = list(FIXER_ORDER)
    if any(f not in FIXERS for f in fixers):
        error_exit(
            f"unknown fixer(s): {[f for f in fixers if f not in FIXERS]} — "
            f"choose from {_FIX_CHOICES}",
            json_mode=json_output,
            code=EXIT_ERROR,
        )

    try:
        patched, reports = run_fixers(built, reference, fixers, layout_dir=layout)
    except (OSError, ValueError, KeyError) as exc:
        error_exit(f"postlink failed: {exc}", json_mode=json_output, code=EXIT_ERROR)

    target = output or built
    # Atomic replace: a crash or disk-full mid-write must not truncate the
    # (by default in-place) built binary.
    atomic_write_bytes(target, patched)

    if json_output:
        json_print(
            {
                "built": str(built),
                "reference": str(reference),
                "layout": str(layout),
                "output": str(target),
                "reports": [r.as_dict() for r in reports],
            }
        )
        return

    for report in reports:
        stats = " ".join(f"{k}={v}" for k, v in report.stats.items())
        detail = f" [{stats}]" if stats else ""
        console.print(
            f"[green]{report.name}:[/] {'changed' if report.changed else 'no change'}{detail}"
        )
        for msg in report.messages:
            console.print(f"  {msg}")


def main_entry() -> None:
    """Run the Typer CLI application.

    The callback is registered as a plain command on a fresh app: the
    group-style ``invoke_without_command`` callback fails to parse
    positional-then-option invocations (``rebrew-<cmd> ARG --opt`` — click
    treats the positional as a command name), while the umbrella's command
    registration parses both orderings (cli-review F1).
    """
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
