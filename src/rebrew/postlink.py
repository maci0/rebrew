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

Architecture notes:

- Each fixer operates on the raw file bytes (``bytearray``) so the output is
  byte-identical; LIEF is used only for parsing (imports, sections, data
  directories).  ``lief.PE.Binary.write()`` re-serializes and would change
  bytes, so header fields are patched at their computed offsets instead.
- Fixers run in dependency order: ``imports`` → ``data`` → ``pe-metadata``
  (the operand rewrites assume the import bookkeeping is already converged).
- ``data`` and ``pe-metadata`` assume the built ``.text`` is position-aligned
  with the reference (functions at the same VAs) — the normal state for a
  decompilation that has passed ``rebrew test``.

Usage:
    rebrew postlink <built.dll> <reference.dll> [--fix imports|data|pe-metadata|all]
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


Fixer = Callable[[bytearray, bytes, BinaryInfo, BinaryInfo], FixerReport]


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


def _data_dir_rva(info: BinaryInfo, index: int) -> int:
    """RVA of data-directory *index* (0=EXPORT_TABLE, 1=IMPORT_TABLE, 5=BASE_RELOC)."""
    e = struct.unpack_from("<I", info.data, 0x3C)[0]
    opt = e + 24
    return int(struct.unpack_from("<I", info.data, opt + 96 + index * 8)[0])


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
    n = struct.unpack_from("<H", info.data, _section_table(info)[0] + 4 + 2)[0]
    for i in range(n):
        h = sec_off + 40 * i
        sn = info.data[h : h + 8].rstrip(b"\x00").decode(errors="replace")
        if sn == name:
            return h
    raise ValueError(f"section {name!r} not found")


# ---------------------------------------------------------------------------
# Fixer 1: imports
# ---------------------------------------------------------------------------


def _import_signature(raw: bytes) -> list[tuple[str | bytes, list[str | bytes | int]]]:
    """Import set as ``[(dll, sorted [entry names or ordinals])]``.

    Entries are *sorted* so the signature is order-insensitive: the MSVC6
    linker assigns IAT slots in a hash-driven order that differs between
    builds, and the whole point of the imports fixer is to converge that
    order — comparing it here would make the fixer refuse the exact case it
    repairs.
    """
    pe = _pe(raw)
    sig: list[tuple[str | bytes, list[str | bytes | int]]] = []
    for imp in pe.imports:
        entries = sorted(
            imp.entries,
            key=lambda e: e.iat_address if e.iat_address else 0,
        )
        names = sorted(e.name if e.name else e.ordinal for e in entries)
        sig.append((imp.name, names))
    return sig


def _fix_imports(
    built: bytearray, ref: bytes, info_b: BinaryInfo, info_r: BinaryInfo
) -> FixerReport:
    """Converge the built import layer onto the reference's.

    For an identical import set the IAT arrays, import descriptors, OFT
    arrays, hint/name records and DLL-name strings contain exactly the same
    bytes as the reference's — the MSVC6 linker just places the records in a
    hash-driven order and may assign IAT slots in a different order.  We
    rewrite the ``.text`` operands that point at moved slots and copy the two
    regions verbatim.
    """
    report = FixerReport(name="imports", changed=False)
    sig_b, sig_r = _import_signature(bytes(built)), _import_signature(ref)
    if sig_b != sig_r:
        raise ValueError(
            "import sets differ — refusing to copy bookkeeping "
            f"(only-in-built={[d for d, _ in sig_b if d not in {n for n, _ in sig_r}]})"
        )

    pe_r = _pe(ref)
    pe_b = _pe(bytes(built))

    def data_dir(pe: lief.PE.Binary, kind: lief.PE.DataDirectory.TYPES) -> tuple[int, int]:
        for d in pe.data_directories:
            if d.type == kind:
                return d.rva, d.size
        return 0, 0

    iat_rva, iat_size = data_dir(pe_r, lief.PE.DataDirectory.TYPES.IAT)
    imp_rva, _ = data_dir(pe_r, lief.PE.DataDirectory.TYPES.IMPORT_TABLE)
    exp_rva, _ = data_dir(pe_r, lief.PE.DataDirectory.TYPES.EXPORT_TABLE)

    # ---- 1. rewrite .text operands that reference moved IAT slots ----
    # Map each entry (by DLL + name/ordinal) to its built and reference slot.
    def slot_map(pe: lief.PE.Binary) -> dict[tuple[str | bytes, str | bytes | int], int]:
        out: dict[tuple[str | bytes, str | bytes | int], int] = {}
        for imp in pe.imports:
            for e in imp.entries:
                key = (imp.name, e.name if e.name else e.ordinal)
                out[key] = e.iat_address
        return out

    slots_b, slots_r = slot_map(pe_b), slot_map(pe_r)
    remap = {slots_b[k]: slots_r[k] for k in slots_b if slots_b[k] != slots_r[k]}
    if remap and iat_rva:
        text = info_b.sections[".text"]
        text_lo = text.file_offset
        text_hi = text.file_offset + text.raw_size
        moved = 0
        for off in range(text_lo, text_hi - 4):
            v = struct.unpack_from("<I", built, off)[0]
            slot = v - info_b.image_base
            if slot in remap and built[off : off + 4] != ref[off : off + 4]:
                struct.pack_into("<I", built, off, remap[slot] + info_b.image_base)
                moved += 1
        report.stats["slot_operands_rewritten"] = moved
        report.changed = report.changed or moved > 0

    # ---- 2. safety: the .rdata prefix must already match ----
    # The hint/name records and OFT arrays are derived from the content before
    # the import directory; if that prefix drifted the copy would be wrong.
    if iat_rva and imp_rva > iat_rva:
        prefix_lo = _rva_to_offset(info_b, iat_rva + iat_size)
        prefix_hi = _rva_to_offset(info_b, imp_rva)
        prefix_r = ref[_rva_to_offset(info_r, iat_rva + iat_size) : _rva_to_offset(info_r, imp_rva)]
        if bytes(built[prefix_lo:prefix_hi]) != prefix_r:
            raise ValueError(
                "built .rdata prefix between the IAT and the import directory "
                "does not match the reference — refusing to copy the import "
                "bookkeeping (check the debug directory: builds with /debug "
                "carry an extra 0x1c-byte directory that shifts everything)"
            )

    # ---- 3. copy the IAT arrays + the import bookkeeping verbatim ----
    if iat_rva and iat_size:
        lo = _rva_to_offset(info_b, iat_rva)
        built[lo : lo + iat_size] = ref[
            _rva_to_offset(info_r, iat_rva) : _rva_to_offset(info_r, iat_rva) + iat_size
        ]
    if imp_rva and exp_rva > imp_rva:
        lo = _rva_to_offset(info_b, imp_rva)
        hi = _rva_to_offset(info_b, exp_rva)
        rlo = _rva_to_offset(info_r, imp_rva)
        rhi = _rva_to_offset(info_r, exp_rva)
        if hi - lo != rhi - rlo:
            raise ValueError(f"import bookkeeping size differs ({hi - lo:#x} vs {rhi - rlo:#x})")
        built[lo:hi] = ref[rlo:rhi]
    report.changed = True
    report.messages.append(
        f"copied IAT ({iat_rva:#x}+{iat_size:#x}) and bookkeeping ({imp_rva:#x}..{exp_rva:#x})"
    )
    return report


# ---------------------------------------------------------------------------
# Fixer 2: data / reloc
# ---------------------------------------------------------------------------


def _fix_data(built: bytearray, ref: bytes, info_b: BinaryInfo, info_r: BinaryInfo) -> FixerReport:
    """Converge ``.data``/``.reloc`` and the ``.text`` data operands.

    The linker's ``.data`` COMDAT order is hash-driven (not source-orderable),
    so once the content is correct the raw ``.data`` is copied from the
    reference.  The ``.text`` operand rewrite covers absolute pointers into
    ``.rdata``/``.data`` (the full VirtualSize, including the BSS tail beyond
    the raw size) and E8/E9 relative call/jump targets.
    """
    report = FixerReport(name="data", changed=False)
    text = info_b.sections[".text"]
    text_r = info_r.sections[".text"]

    # operand ranges, image-base-relative
    lo_r = info_r.sections[".rdata"].va - info_r.image_base
    hi_r = info_r.sections[".rdata"].va - info_r.image_base + info_r.sections[".rdata"].size
    data_va = info_r.sections[".data"].va - info_r.image_base
    lo_d = data_va
    hi_d = data_va + info_r.sections[".data"].size  # full VS (raw + BSS)

    def in_range(v: int) -> bool:
        return lo_r <= v < hi_r or lo_d <= v < hi_d

    # ---- 1. absolute data operands (every offset — x86 operands are
    # misaligned, a 4-byte-aligned scan misses most of them) ----
    operands = 0
    for off in range(text.file_offset, text.file_offset + text.raw_size - 4):
        va = struct.unpack_from("<I", built, off)[0]
        vb = struct.unpack_from("<I", ref, off)[0]
        if va != vb and in_range(va - info_b.image_base) and in_range(vb - info_r.image_base):
            struct.pack_into("<I", built, off, vb)
            operands += 1
    report.stats["data_operands"] = operands
    report.changed = report.changed or operands > 0

    # ---- 2. E8/E9 relative call/jump targets (context-matched) ----
    rel32 = 0
    for off in range(text.file_offset + 1, text.file_offset + text.raw_size - 6):
        if built[off] == ref[off]:
            continue
        if (
            built[off - 1] in (0xE8, 0xE9)
            and ref[off - 1] in (0xE8, 0xE9)
            and built[off - 3 : off - 1] == ref[off - 3 : off - 1]
            and built[off + 4 : off + 6] == ref[off + 4 : off + 6]
        ):
            struct.pack_into("<I", built, off, struct.unpack_from("<I", ref, off)[0])
            rel32 += 1
    report.stats["call_targets"] = rel32
    report.changed = report.changed or rel32 > 0

    # ---- 3. trim the extra .text tail + fix .text VirtualSize ----
    text_end = text_r.file_offset + text_r.size  # reference content end
    if text_end < text.file_offset + text.raw_size:
        built[text_end : text.file_offset + text.raw_size] = b"\x00" * (
            text.file_offset + text.raw_size - text_end
        )
        struct.pack_into("<I", built, _section_header_offset(info_b, ".text") + 8, text_r.size)
        report.changed = True

    # ---- 4. grow .data to the reference raw size and copy it ----
    data_b = info_b.sections[".data"]
    data_r = info_r.sections[".data"]
    if data_r.raw_size > len(built):
        built.extend(b"\x00" * (data_r.raw_size - len(built)))
    built[data_b.file_offset : data_b.file_offset + data_r.raw_size] = ref[
        data_r.file_offset : data_r.file_offset + data_r.raw_size
    ]
    struct.pack_into("<I", built, _section_header_offset(info_b, ".data") + 16, data_r.raw_size)

    # ---- 5. replace .reloc (at the reference's file offset) ----
    reloc_b = info_b.sections[".reloc"]
    reloc_r = info_r.sections[".reloc"]
    new_rptr = reloc_r.file_offset
    if new_rptr + reloc_r.raw_size > len(built):
        built.extend(b"\x00" * (new_rptr + reloc_r.raw_size - len(built)))
    built[new_rptr : new_rptr + reloc_r.raw_size] = ref[
        reloc_r.file_offset : reloc_r.file_offset + reloc_r.raw_size
    ]
    h = _section_header_offset(info_b, ".reloc")
    struct.pack_into("<I", built, h + 8, reloc_r.size)  # VirtualSize
    struct.pack_into("<I", built, h + 16, reloc_r.raw_size)
    struct.pack_into("<I", built, h + 20, new_rptr)
    # .reloc data directory size
    e, opt, _ = _section_table(info_b)
    dd = opt + 96
    for i in range(16):
        rva = struct.unpack_from("<I", built, dd + 8 * i)[0]
        if rva == reloc_b.va - info_b.image_base:
            struct.pack_into("<I", built, dd + 8 * i + 4, reloc_r.size)
            break
    report.changed = True
    report.messages.append(
        f".data -> {data_r.raw_size:#x} bytes; .reloc -> {reloc_r.raw_size:#x} "
        f"bytes at {new_rptr:#x}"
    )
    return report


# ---------------------------------------------------------------------------
# Fixer 3: PE metadata
# ---------------------------------------------------------------------------


def _fix_pe_metadata(
    built: bytearray, ref: bytes, info_b: BinaryInfo, info_r: BinaryInfo
) -> FixerReport:
    """Normalize toolchain-stamped PE metadata against the reference.

    The MSVC6 link step stamps the DOS stub (Rich header / different
    ``e_lfanew``), ``TimeDateStamp``, an empty CheckSum, a too-small ``.data``
    VirtualSize (BSS placeholders are emitted as ``char[1]``), and a
    ``.reloc`` VA that predates the BSS growth.  None of these are decomp
    content; this fixer copies the reference's header/stub values.
    """
    report = FixerReport(name="pe-metadata", changed=False)
    b = built
    r = ref

    e_b, opt_b, sec_b = _section_table(info_b)
    e_r, opt_r, sec_r = _section_table(info_r)

    # ---- 1. DOS stub + e_lfanew (header block is relocated losslessly) ----
    if e_b != e_r or b[:e_r] != r[:e_r]:
        coff = e_b + 4
        n = struct.unpack_from("<H", b, coff + 2)[0]
        opt_size = struct.unpack_from("<H", b, coff + 16)[0]
        hdr_size = 4 + 20 + opt_size + n * 40
        if e_r + hdr_size > 0x1000:
            raise ValueError("headers would overlap the first section")
        new = bytearray()
        new += r[:e_r]  # reference DOS stub (carries e_lfanew = e_r)
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
    n_r = struct.unpack_from("<H", r, e_r + 4 + 2)[0]
    opt_size_b = struct.unpack_from("<H", b, e_b + 4 + 16)[0]
    opt_size_r = struct.unpack_from("<H", r, e_r + 4 + 16)[0]

    def names_at(raw: bytes | bytearray, e: int, n: int, opt_size: int) -> list[str]:
        sec_off = e + 4 + 20 + opt_size
        return [
            raw[sec_off + 40 * i : sec_off + 40 * i + 8].rstrip(b"\x00").decode(errors="replace")
            for i in range(n)
        ]

    hdr_size_r = 4 + 20 + opt_size_r + n_r * 40
    if n_b == n_r and names_at(b, e_b, n_b, opt_size_b) == names_at(r, e_r, n_r, opt_size_r):
        b[e_b : e_b + hdr_size_r] = r[e_r : e_r + hdr_size_r]
        report.changed = True
    else:
        # Section layout not converged — fall back to stamping only the
        # fields that are safe regardless of layout.
        ts = struct.unpack_from("<I", r, e_r + 4 + 4)[0]
        if struct.unpack_from("<I", b, e_b + 4 + 4)[0] != ts:
            struct.pack_into("<I", b, e_b + 4 + 4, ts)
            report.changed = True
        cs_r = struct.unpack_from("<I", r, opt_r + 64)[0]
        if struct.unpack_from("<I", b, opt_b + 64)[0] != cs_r:
            struct.pack_into("<I", b, opt_b + 64, cs_r)
            report.changed = True

    # ---- 3. copy the export-dir stamp pair ----
    # LINK writes the link time into the export directory's TimeDateStamp
    # (and Characteristics); the original carries its own values.  Copy the
    # 8-byte Characteristics+TimeDateStamp pair verbatim.
    exp_rva = _data_dir_rva(info_r, 0)  # EXPORT_TABLE
    if exp_rva:
        eo_b = _rva_to_offset(info_b, exp_rva)
        eo_r = _rva_to_offset(info_r, exp_rva)
        if eo_b is not None and eo_r is not None and b[eo_b : eo_b + 8] != r[eo_r : eo_r + 8]:
            b[eo_b : eo_b + 8] = r[eo_r : eo_r + 8]
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
    built_path: Path, reference_path: Path, fixer_names: Iterable[str] | None = None
) -> tuple[bytes, list[FixerReport]]:
    """Apply the named fixers (default: all) to *built_path*.

    Returns the patched bytes and the per-fixer reports.  Raises ``ValueError``
    if a fixer's preconditions are not met (import set mismatch, drifted
    prefix, etc.).
    """
    info_b = load_binary(built_path)
    info_r = load_binary(reference_path)
    built = bytearray(info_b.data)
    ref = bytes(info_r.data)

    names = list(fixer_names) if fixer_names else list(FIXER_ORDER)
    unknown = [n for n in names if n not in FIXERS]
    if unknown:
        raise ValueError(f"unknown fixers: {', '.join(unknown)}")
    names = [n for n in FIXER_ORDER if n in names]  # dependency order

    reports: list[FixerReport] = []
    for name in names:
        before = bytes(built)
        report = FIXERS[name](built, ref, info_b, info_r)
        report.changed = before != bytes(built)  # byte-diff is authoritative
        reports.append(report)
    return bytes(built), reports


def _reference_from_layout(layout_json: Path) -> Path:
    """Reconstruct a reference image from a ``gen-layout`` package.

    The package (``layout/<target>/``) holds the original's header block
    (hex) and raw section blobs, so ``postlink`` can run without the
    original DLL.  Returns the path of a temporary reconstructed image.
    """
    import json
    import tempfile

    manifest = json.loads(layout_json.read_text())
    pkg = layout_json.parent
    hdr = bytes.fromhex(manifest["header_block_hex"])
    img_size = len(hdr)
    blobs: dict[str, bytes] = {}
    for s in manifest["sections"]:
        blob = (pkg / manifest["section_files"][s["name"]]).read_bytes()
        blobs[s["name"]] = blob
        img_size = max(img_size, s["raw_ptr"] + s["raw_size"])
    img = bytearray(img_size)
    img[: len(hdr)] = hdr
    for s in manifest["sections"]:
        blob = blobs[s["name"]]
        img[s["raw_ptr"] : s["raw_ptr"] + len(blob)] = blob
    with tempfile.NamedTemporaryFile(prefix="rebrew-layout-", suffix=".dll", delete=False) as tmp:
        tmp.write(bytes(img))
    return Path(tmp.name)


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
        None, help="Reference binary to converge onto (omit when --layout is used)"
    ),
    layout: Path | None = typer.Option(
        None,
        "--layout",
        help="link_layout.json from 'rebrew gen-layout' — reconstruct the reference "
        "from the project layout package instead of a reference binary",
    ),
    fix: str = typer.Option(
        "all",
        "--fix",
        help="Fixer(s) to run: all, imports, data, pe-metadata (repeatable; defaults to all)",
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

    Either pass the reference DLL directly, or ``--layout`` pointing at the
    ``link_layout.json`` produced by ``rebrew gen-layout`` (the layout
    package carries the original's header block and section bytes, so the
    original DLL is not needed at fix time).
    """
    if not built.exists():
        error_exit(f"built binary not found: {built}", json_mode=json_output, code=EXIT_ERROR)
    if layout is not None:
        if not layout.exists():
            error_exit(
                f"layout manifest not found: {layout}", json_mode=json_output, code=EXIT_ERROR
            )
        reference = _reference_from_layout(layout)
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
        patched, reports = run_fixers(built, reference, fixers)
    except (OSError, ValueError, KeyError) as exc:
        error_exit(f"postlink failed: {exc}", json_mode=json_output, code=EXIT_ERROR)

    target = output or built
    target.write_bytes(patched)

    if json_output:
        json_print(
            {
                "built": str(built),
                "reference": str(reference),
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
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
