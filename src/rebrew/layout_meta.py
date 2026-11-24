"""layout_meta.py — text-only layout metadata for byte-identical post-linking.

The MSVC6 linker cannot be made to reproduce the reference's import-record
placement, ``.data`` COMDAT order, ``.reloc`` set, or toolchain-stamped PE
header, so ``rebrew build postlink`` converges the built binary onto the
reference after the link.  Those reference bytes used to be snapshotted as
a binary package (``layout/<target>.zip`` with raw section blobs), which
cannot be committed to a public repo.

This module defines the replacement: a *text-only* layout package whose
bytes are the least amount of verbatim content the fixers actually need,
everything else reconstructed from structured metadata:

``layout/<target>/rebrew-layout.toml``
    Structured metadata (TOML): image base, sections (VA/virtual size/raw
    size/raw pointer/characteristics), exports, imports (with their
    reference IAT-slot VAs), link options, export-directory stamp pair.

``layout/<target>/header.hex``
    The full reference header block (DOS stub + PE sig + COFF + optional
    header + section table, ``[0 : e_lfanew + header_size]``).  All of it is
    linker-stamped and opaque (Rich header, timestamp, checksum, the
    two-phase SizeOfImage/BaseOfData artifact), so it is stored verbatim —
    as hex text, 536 bytes.

``layout/<target>/iat.hex``
    The reference IAT array (``.rdata`` start).  Its slot order is the
    linker's hash-driven assignment and cannot be forced, so the bytes are
    stored verbatim (416 bytes) and the slot map per symbol lives in
    ``rebrew-layout.toml``.

``layout/<target>/prefix.hex``
    The reference ``.rdata`` prefix between the IAT and the import
    directory (hint/name records, OFT arrays, DLL names).  The fixer only
    *checks* it for drift (a ``/debug`` build shifts everything) — it is
    never copied — but the check needs the reference bytes (9.3 KB).

``layout/<target>/bookkeeping.hex``
    The reference import bookkeeping region ``[imp_rva : exp_rva)``
    (descriptors + trailing records, 2 KB) — copied verbatim.

``layout/<target>/data.hex``
    The reference ``.data`` raw content (``0xe000`` bytes).  The built
    ``.data`` carries the same values in the linker's COMDAT order, so the
    reference order is copied over it.  Stored verbatim as hex text.

``layout/<target>/reloc.hex``
    The reference ``.reloc`` *content* (relocation blocks only, not the
    zero padding to the section's raw size).

``layout/<target>/operands.txt``
    Sparse map of ``.text``-relative offset → reference 32-bit value, for
    every position where the reference holds an image-relative address
    (``.rdata``/``.data`` pointer).  The fixer rewrites a built operand
    only where it differs; the map tells it the reference value.

``layout/<target>/calls.txt``
    Sparse map of ``.text``-relative offset → (rel32, 2-byte prefix, 2-byte
    suffix, opcode) for every E8/E9 relative call/jump in the reference.  The
    fixer rewrites only where the built differs and the instruction
    context matches, exactly like the old byte-scan did.

All files are plain text (``#`` comment lines allowed in the hex dumps);
``extract_layout`` derives the package from a binary, ``write_package`` /
``load_package`` serialize it.  ``rebrew build layout`` emits it during intake;
``rebrew build postlink --layout <dir>`` consumes it, so the original DLL never needs
to be present at build time.
"""

from __future__ import annotations

import dataclasses
from typing import Any
lazy import struct
lazy from collections.abc import Callable
lazy from pathlib import Path

lazy from rebrew.formats.pe_headers import pe_header, sections_at
lazy from rebrew.utils import atomic_write_text, last_change_ns

#: Cap on import name-table / descriptor slots read from one PE.  A missing
#: null terminator would otherwise walk past EOF into ``struct.error``.
_MAX_IMPORT_SLOTS = 65536

#: Cap on export AddressOfFunctions / AddressOfNames entries.  A forged
#: NumberOfNames/NumberOfFunctions of ``0xFFFFFFFF`` would otherwise hang in
#: ``range()`` or raise ``struct.error`` past EOF.
_MAX_EXPORT_ENTRIES = 65536

#: Widths of the PE fields the post-link fixers write layout values back into:
#: section geometry, RVAs, stamps and operands are dwords; call-context bytes
#: and import ordinals are words.
_U32_MAX = 0xFFFFFFFF
_U16_MAX = 0xFFFF

#: Bound for the geometry readers (``read_layout_geometry``,
#: ``read_layout_header``): the package ``splat_config`` writes for a PE32+ or
#: ELF image can record an image base wider than a dword.
_U64_MAX = (1 << 64) - 1

#: Integer geometry keys of one ``rebrew-layout.toml`` section row.
_SECTION_KEYS = ("va", "vs", "raw", "ptr", "chars")


# ---------------------------------------------------------------------------
# Field validation for the hand-editable package text
# ---------------------------------------------------------------------------


def _field(table: dict[str, Any], key: str, where: str) -> Any:
    """``table[key]``, or ``ValueError`` naming the missing key."""
    if key not in table:
        raise ValueError(f"layout package {where} has no {key!r}")
    return table[key]


def _table(value: Any, where: str) -> dict[str, Any]:
    """*value* as a TOML table, or ``ValueError``."""
    if not isinstance(value, dict):
        raise ValueError(f"layout package {where} must be a table")
    return value


def _array(value: Any, where: str) -> list[Any]:
    """*value* as a TOML array, or ``ValueError``."""
    if not isinstance(value, list):
        raise ValueError(f"layout package {where} must be an array")
    return value


def _string(value: Any, where: str) -> str:
    """*value* as a string, or ``ValueError``."""
    if not isinstance(value, str):
        raise ValueError(f"layout package {where} must be a string")
    return str(value)


def _uint(value: Any, where: str, limit: int = _U32_MAX) -> int:
    """*value* as an integer in ``[0, limit]``, or ``ValueError``.

    TOML booleans are Python ``bool``, an ``int`` subclass, so they are
    refused explicitly.
    """
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= limit:
        raise ValueError(f"layout package {where} must be an integer in [0, {limit:#x}]")
    return int(value)


def _section_rows(value: Any, where: str) -> list[dict[str, Any]]:
    """*value* as the ``sections`` array of tables at *where*."""
    rows = _array(value, f"{where}.sections")
    return [_table(row, f"{where}.sections[{n}]") for n, row in enumerate(rows)]


@dataclasses.dataclass
class SectionMeta:
    """One PE section header, in the field names the export format uses."""

    name: str
    va: int
    vs: int
    raw: int
    raw_ptr: int
    chars: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "va": self.va,
            "vs": self.vs,
            "raw": self.raw,
            "ptr": self.raw_ptr,
            "chars": self.chars,
        }


@dataclasses.dataclass
class ImportMeta:
    """One import slot: by name, or by ordinal when *name* is ``None``."""

    dll: str
    name: str | None  # None = ordinal-only
    ordinal: int | None
    iat_va: int  # reference IAT slot address

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"dll": self.dll, "iat": self.iat_va}
        if self.name is not None:
            out["name"] = self.name
        if self.ordinal is not None:
            out["ordinal"] = self.ordinal
        return out


@dataclasses.dataclass
class LayoutMetadata:
    """Complete reference layout for the post-link fixers, text-serializable."""

    target: str
    image_base: int
    link_options: list[str]
    sections: list[SectionMeta]
    exports: list[dict[str, Any]]
    imports: list[ImportMeta]
    header: bytes
    iat: bytes
    prefix: bytes
    bookkeeping: bytes
    data: bytes
    reloc: bytes
    operands: dict[int, int]  # .text-relative offset → reference value
    calls: dict[
        int, tuple[int, int, int, int | None]
    ]  # .text-relative off → (rel32, prefix2, suffix2, opcode); None for old packages
    exp_rva: int  # export directory RVA (end of the import bookkeeping)
    export_stamp: tuple[int, int]  # (Characteristics, TimeDateStamp)

    # -- convenience accessors -------------------------------------------

    def section(self, name: str) -> SectionMeta:
        for s in self.sections:
            if s.name == name:
                return s
        raise KeyError(name)

    def as_dict(self) -> dict[str, Any]:
        """Structured metadata as a plain dict (the ``rebrew-layout.toml`` content)."""
        return {
            "target": self.target,
            "image_base": self.image_base,
            "link_options": self.link_options,
            "sections": [s.as_dict() for s in self.sections],
            "exports": self.exports,
            "imports": [i.as_dict() for i in self.imports],
            "export_stamp": list(self.export_stamp),
            "exp_rva": self.exp_rva,
        }


def read_layout_geometry(root: Path, target: str) -> tuple[int, int, int]:
    """``(data_base, raw_end, section_end)`` from ``layout/<target>/rebrew-layout.toml``.

    The single reader for layout geometry — the package is the source of
    truth, not a TOML block in rebrew-project.toml.  A malformed package is a
    ``ValueError``, like a missing one.
    """
    import tomllib

    txt = Path(root) / "layout" / target / "rebrew-layout.toml"
    try:
        raw = tomllib.loads(txt.read_text(encoding="utf-8-sig"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(
            f"no layout package at {txt} (run rebrew build layout first): {exc}"
        ) from exc
    lay = _table(raw.get("layout", {}), f"{txt} [layout]")
    base = _uint(lay.get("image_base", 0), f"{txt} layout.image_base", _U64_MAX)
    for n, s in enumerate(_section_rows(lay.get("sections", []), f"{txt} layout")):
        if s.get("name") == ".data":
            where = f"{txt} layout.sections[{n}]"
            va, raw_sz, vs = (
                _uint(_field(s, k, where), f"{where}.{k}", _U64_MAX) for k in ("va", "raw", "vs")
            )
            return base + va, base + va + raw_sz, base + va + vs
    raise ValueError(f"no .data section in {txt} (run rebrew build layout first)")


def read_layout_header(root: Path, target: str, bin_path: Path) -> dict[str, Any] | None:
    """Header facts from ``layout/<target>/rebrew-layout.toml`` — no LIEF.

    Returns ``{"image_base", "text_va", "text_size", "text_raw_offset",
    "sections": [(name, va, vs, raw, ptr), ...]}`` with every section
    ``va`` as an absolute VA, or ``None`` when the package is missing,
    malformed, or **stale** (older than *bin_path*) — callers then fall
    back to LIEF on the binary.  Reading the committed layout package
    instead of parsing the binary removes LIEF's ~0.11 s import from
    status/lint startup.
    """
    import tomllib

    txt = Path(root) / "layout" / target / "rebrew-layout.toml"
    try:
        if last_change_ns(bin_path.stat()) > txt.stat().st_mtime_ns:
            return None  # binary rebuilt after rebrew build layout — parse it instead
        where = f"{txt} layout"
        lay = _table(
            _field(tomllib.loads(txt.read_text(encoding="utf-8-sig")), "layout", str(txt)),
            where,
        )
        base = _uint(lay.get("image_base", 0), f"{where}.image_base", _U64_MAX)
        sections: list[tuple[str, int, int, int, int]] = []
        text_va = text_size = text_raw = 0
        for n, s in enumerate(_section_rows(lay.get("sections", []), where)):
            row = f"{where}.sections[{n}]"
            name = str(s.get("name") or "")
            va = base + _uint(s.get("va", 0), f"{row}.va", _U64_MAX)
            rec = (
                name,
                va,
                _uint(s.get("vs", 0), f"{row}.vs", _U64_MAX),
                _uint(s.get("raw", 0), f"{row}.raw", _U64_MAX),
                _uint(s.get("ptr", 0), f"{row}.ptr", _U64_MAX),
            )
            sections.append(rec)
            if name == ".text":
                text_va, text_size, text_raw = rec[1], rec[2], rec[4]
    except OSError, ValueError:
        return None
    if not sections:
        return None
    return {
        "image_base": base,
        "text_va": text_va,
        "text_size": text_size,
        "text_raw_offset": text_raw,
        "sections": sections,
    }


# ---------------------------------------------------------------------------
# Extraction from a binary
# ---------------------------------------------------------------------------


def _data_dir(data: bytes, opt: int, index: int) -> tuple[int, int]:
    """Data directory *index*, or ``ValueError`` when it lies past EOF.

    Index 12 (IAT) is the deepest directory ``extract_layout`` reads.  A PE32
    whose optional header is present but shorter than that directory used to
    raise ``struct.error``, which ``rebrew build layout`` does not catch.
    """
    off = opt + 96 + 8 * index
    if off + 8 > len(data):
        raise ValueError("truncated optional header")
    return struct.unpack_from("<II", data, off)


def extract_layout(data: bytes, target: str = "") -> LayoutMetadata:
    """Derive the full text-only layout metadata from a reference binary."""
    e, nsec, optsz, opt, image_base = pe_header(data)
    header_size = e + 4 + 20 + optsz + nsec * 40
    sh = opt + optsz

    sections: list[SectionMeta] = [
        SectionMeta(
            s.name,
            s.virtual_address,
            s.virtual_size,
            s.size_of_raw_data,
            s.pointer_to_raw_data,
            s.characteristics,
        )
        for s in sections_at(data, sh, nsec)
    ]

    def off(rva: int) -> int | None:
        for s in sections:
            if s.va <= rva < s.va + max(s.vs, s.raw):
                return s.raw_ptr + (rva - s.va)
        return None

    iat_rva, iat_size = _data_dir(data, opt, 12)  # IAT
    imp_rva, _ = _data_dir(data, opt, 1)  # IMPORT_TABLE
    exp_rva, exp_sz = _data_dir(data, opt, 0)  # EXPORT_TABLE

    def region(rva: int, size: int) -> bytes:
        o = off(rva)
        if o is None or o + size > len(data):
            raise ValueError(f"region rva=0x{rva:x} size={size:#x} out of range")
        return data[o : o + size]

    def cstr(o: int) -> str:
        end = data.find(b"\0", o)
        if end < 0:
            end = len(data)  # unterminated — read to EOF, not to -1
        return data[o:end].decode("latin1", "replace")

    header = data[:header_size]
    iat = region(iat_rva, iat_size) if iat_rva else b""
    prefix = (
        region(iat_rva + iat_size, imp_rva - (iat_rva + iat_size))
        if iat_rva and imp_rva > iat_rva + iat_size
        else b""
    )
    # [imp_rva : exp_rva) needs the export directory as its end.  A binary
    # without exports (EXE, stripped-export DLL) has exp_rva == 0, which made
    # the size negative; `region` only rejects `o + size > len(data)`, so a
    # negative size sliced a huge wrong region that postlink then copied over
    # the built binary.
    bookkeeping = region(imp_rva, exp_rva - imp_rva) if imp_rva and exp_rva > imp_rva else b""

    def find_sec_opt(name: str) -> SectionMeta | None:
        return next((s for s in sections if s.name == name), None)

    def find_sec(name: str) -> SectionMeta:
        if (s := find_sec_opt(name)) is None:
            raise ValueError(f"missing section {name!r} (layout needs .text/.data/.rdata)")
        return s

    data_sec = find_sec(".data")
    reloc_sec = find_sec_opt(".reloc")
    rdata_sec = find_sec(".rdata")
    text_sec = find_sec(".text")

    # .data raw content, verbatim
    data_bytes = data[data_sec.raw_ptr : data_sec.raw_ptr + data_sec.raw]

    # .reloc content = relocation blocks only; the fixer zero-fills the rest
    # of the section's raw size (MSVC6 rounds raw up, padding with zeros).
    # Binaries linked without relocations (stripped game EXEs) have no
    # .reloc section — the fixer gets empty bytes, not an error.
    if reloc_sec is None:
        reloc_bytes = b""
    else:
        # The fixer's zero fill reproduces raw bytes, so they must be in the
        # file: a forged SizeOfRawData would size a multi-gigabyte fill.
        reloc_end = reloc_sec.raw_ptr + reloc_sec.raw
        if reloc_end > len(data):
            raise ValueError(
                f".reloc raw data ends at {reloc_end:#x}, past the end of the "
                f"{len(data):#x}-byte file"
            )
        rblob = data[reloc_sec.raw_ptr : reloc_end]
        content_end = 0
        while content_end + 8 <= len(rblob):
            _page, blksz = struct.unpack_from("<II", rblob, content_end)
            if blksz == 0 or blksz > len(rblob) - content_end:
                break
            content_end += blksz
        reloc_bytes = rblob[:content_end]

    # sparse .text rewrite maps (offsets relative to .text raw start)
    tb = data[text_sec.raw_ptr : text_sec.raw_ptr + text_sec.raw]
    lo_r = rdata_sec.va
    hi_r = rdata_sec.va + rdata_sec.vs
    lo_d = data_sec.va
    hi_d = data_sec.va + data_sec.vs

    operands: dict[int, int] = {}
    # i reads tb[i:i+4]; the last dword starts at len(tb)-4.
    for i in range(len(tb) - 3):
        v = struct.unpack_from("<I", tb, i)[0]
        rva = v - image_base
        if (lo_r <= rva < hi_r) or (lo_d <= rva < hi_d):
            operands[i] = v

    calls: dict[int, tuple[int, int, int, int | None]] = {}
    # i reads tb[i+4:i+6]; the last suffix ends at len(tb)-6.
    for i in range(3, len(tb) - 5):
        if tb[i - 1] in (0xE8, 0xE9):
            rel32 = struct.unpack_from("<I", tb, i)[0]
            pre = int.from_bytes(tb[i - 3 : i - 1], "big")
            suf = int.from_bytes(tb[i + 4 : i + 6], "big")
            calls[i] = (rel32, pre, suf, tb[i - 1])

    # export directory Characteristics+TimeDateStamp pair
    export_stamp = (0, 0)
    if exp_rva:
        eo = off(exp_rva)
        if eo is not None and eo + 8 <= len(data):
            export_stamp = struct.unpack_from("<II", data, eo)

    # imports with reference IAT slot VAs
    imports: list[ImportMeta] = []
    import_slots = 0
    if imp_rva:
        io = off(imp_rva)
        if io is not None:
            # The lookup table is the OriginalFirstThunk (OFT) — except when
            # the linker left OFT unbound (0), in which case the import
            # *is* bound by the IAT itself (standard PE rule) and the IAT
            # must be used as the lookup table instead of skipping the
            # import or parsing the header region at oft(0) as hint/names.
            for i in range(_MAX_IMPORT_SLOTS):
                if io + i * 20 + 20 > len(data):
                    break
                oft, _ts, _fwd, name_rva, iat_va = struct.unpack_from("<IIIII", data, io + i * 20)
                if oft == 0 and name_rva == 0:
                    break
                dll_off = off(name_rva)
                dll = "?" if dll_off is None else cstr(dll_off)
                lookup_rva = oft or iat_va
                oo = off(lookup_rva) if lookup_rva else None
                if oo is None:
                    continue
                for j in range(_MAX_IMPORT_SLOTS):
                    slot_off = oo + 4 * j
                    if slot_off + 4 > len(data):
                        break
                    nm = struct.unpack_from("<I", data, slot_off)[0]
                    if nm == 0:
                        break
                    import_slots += 1
                    if import_slots > _MAX_IMPORT_SLOTS:
                        raise ValueError("PE import slot limit exceeded")
                    if nm & 0x80000000:
                        imports.append(ImportMeta(dll, None, nm & 0xFFFF, iat_va + 4 * j))
                    else:
                        no = off(nm)
                        if no is not None:
                            imports.append(ImportMeta(dll, cstr(no + 2), None, iat_va + 4 * j))

    exports: list[dict[str, Any]] = []
    eo = off(exp_rva)
    # IMAGE_EXPORT_DIRECTORY is 40 bytes; require the full header before
    # reading counts / RVAs, and cap table walks like the import path.
    if eo is not None and exp_sz and eo + 40 <= len(data):
        nfuncs = min(struct.unpack_from("<I", data, eo + 20)[0], _MAX_EXPORT_ENTRIES)
        nnames = min(struct.unpack_from("<I", data, eo + 24)[0], _MAX_EXPORT_ENTRIES)
        funcs_off = off(struct.unpack_from("<I", data, eo + 28)[0])
        names_off = off(struct.unpack_from("<I", data, eo + 32)[0])
        ords_off = off(struct.unpack_from("<I", data, eo + 36)[0])
        ordinal_base = struct.unpack_from("<I", data, eo + 16)[0]
        name_by_ord: dict[int, str] = {}
        for k in range(nnames):
            if names_off is not None and names_off + 4 * (k + 1) > len(data):
                break
            if ords_off is not None and ords_off + 2 * (k + 1) > len(data):
                break
            nrva = struct.unpack_from("<I", data, names_off + 4 * k)[0] if names_off else 0
            ord_idx = struct.unpack_from("<H", data, ords_off + 2 * k)[0] if ords_off else 0
            nm_off = off(nrva)
            if nm_off is not None:
                name_by_ord[ordinal_base + ord_idx] = cstr(nm_off)
        for k in range(nfuncs):
            if funcs_off is not None and funcs_off + 4 * (k + 1) > len(data):
                break
            addr = struct.unpack_from("<I", data, funcs_off + 4 * k)[0] if funcs_off else 0
            if addr == 0:
                continue
            if exp_rva <= addr < exp_rva + exp_sz:
                # Forwarder: the RVA points at a forwarder string inside the
                # export directory, not at code (pe_image.parse_pe drops
                # these too).  Recording it would claim a function at a .rdata VA.
                continue
            exports.append(
                {
                    "name": name_by_ord.get(ordinal_base + k),
                    "ordinal": ordinal_base + k,
                    "va": image_base + addr,
                }
            )

    return LayoutMetadata(
        target=target,
        image_base=image_base,
        link_options=[],
        sections=sections,
        exports=exports,
        imports=imports,
        header=header,
        iat=iat,
        prefix=prefix,
        bookkeeping=bookkeeping,
        data=data_bytes,
        reloc=reloc_bytes,
        operands=operands,
        calls=calls,
        exp_rva=exp_rva,
        export_stamp=export_stamp,
    )


# ---------------------------------------------------------------------------
# Text package serialization
# ---------------------------------------------------------------------------


def _from_hex(text: str) -> bytes:
    compact = "".join(
        line.strip() for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    return bytes.fromhex(compact)


def _sparse_lines(entries: list[tuple[int, ...]]) -> str:
    return "\n".join(" ".join(f"0x{x:x}" for x in e) for e in entries) + ("\n" if entries else "")


def _parse_sparse(text: str) -> list[tuple[int, ...]]:
    out: list[tuple[int, ...]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        from rebrew.utils import parse_int_literal

        out.append(tuple(parse_int_literal(x) for x in line.split()))
    return out


def write_package(
    meta: LayoutMetadata, out_dir: Path, fmt_toml: Callable[[LayoutMetadata], str]
) -> list[Path]:
    """Write the text-only layout package into *out_dir*.

    *fmt_toml* is a callable(meta) -> str that renders the
    ``rebrew-layout.toml`` (the caller owns the exact TOML rendering — the
    package's core file is never silently skipped).  Returns the written
    paths.
    """

    calls: list[tuple[int, ...]] = []
    for off, (rel32, pre, suf, opcode) in sorted(meta.calls.items()):
        if opcode is None or opcode not in (0xE8, 0xE9):
            raise ValueError(
                "layout call opcode is unknown; re-extract the reference before writing"
            )
        calls.append((off, rel32, pre, suf, opcode))
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    blobs = {
        "header.hex": meta.header,
        "iat.hex": meta.iat,
        "prefix.hex": meta.prefix,
        "bookkeeping.hex": meta.bookkeeping,
        "data.hex": meta.data,
        "reloc.hex": meta.reloc,
    }
    for name, blob in blobs.items():
        p = out_dir / name
        head = f"# {meta.target} - {name}: {len(blob)} bytes\n# generated by rebrew build layout; do not hand-edit\n"
        atomic_write_text(p, head + blob.hex("\n", -32) + "\n", encoding="utf-8")
        written.append(p)

    ops = sorted(meta.operands.items())
    p = out_dir / "operands.txt"
    atomic_write_text(
        p,
        f"# {meta.target} - .text data-operand map: '.text-relative-offset value'\n"
        "# generated by rebrew build layout; do not hand-edit\n"
        + _sparse_lines([(o, v) for o, v in ops]),
        encoding="utf-8",
    )
    written.append(p)

    p = out_dir / "calls.txt"
    atomic_write_text(
        p,
        f"# {meta.target} - .text E8/E9 map: '.text-relative-offset rel32 prefix2 suffix2 opcode'\n"
        "# generated by rebrew build layout; do not hand-edit\n" + _sparse_lines(calls),
        encoding="utf-8",
    )
    written.append(p)

    p = out_dir / "rebrew-layout.toml"
    atomic_write_text(p, fmt_toml(meta), encoding="utf-8")
    written.append(p)
    return written


def load_package(pkg_dir: Path) -> LayoutMetadata:
    """Load a text-only layout package written by :func:`write_package`.

    The package is generated plain text, but the loader validates it as
    untrusted input: a missing key, a wrong type, a value outside the PE field
    the fixers write it into, a sparse-map row of the wrong length, a header
    block that is not a whole PE32 header, or a section list whose length
    differs from that header's section count raises ``ValueError``.  A missing
    sparse-map file is an ``OSError``.
    """
    import tomlkit

    pkg = Path(pkg_dir)
    if not (pkg / "rebrew-layout.toml").exists():
        raise ValueError(
            f"layout package {pkg} is missing rebrew-layout.toml — expected the text "
            "package from 'rebrew build layout' (layout/<target>/), not a binary"
        )

    def blob(name: str) -> bytes:
        p = pkg / name
        if not p.exists():
            raise ValueError(f"layout package missing {name} (run 'rebrew build layout')")
        return _from_hex(p.read_text(encoding="utf-8"))

    structured = tomlkit.parse((pkg / "rebrew-layout.toml").read_text(encoding="utf-8-sig"))
    lay = _table(_field(structured, "layout", "rebrew-layout.toml"), "layout")

    sections: list[SectionMeta] = []
    for n, s in enumerate(_section_rows(_field(lay, "sections", "layout"), "layout")):
        where = f"layout.sections[{n}]"
        geometry = {k: _uint(_field(s, k, where), f"{where}.{k}") for k in _SECTION_KEYS}
        sections.append(
            SectionMeta(
                name=_string(_field(s, "name", where), f"{where}.name"),
                va=geometry["va"],
                vs=geometry["vs"],
                raw=geometry["raw"],
                raw_ptr=geometry["ptr"],
                chars=geometry["chars"],
            )
        )

    imports: list[ImportMeta] = []
    for n, entry in enumerate(_array(_field(lay, "imports", "layout"), "layout.imports")):
        where = f"layout.imports[{n}]"
        imp = _table(entry, where)
        name = imp.get("name")
        ordinal = imp.get("ordinal")
        imports.append(
            ImportMeta(
                dll=_string(_field(imp, "dll", where), f"{where}.dll"),
                name=None if name is None else _string(name, f"{where}.name"),
                ordinal=None if ordinal is None else _uint(ordinal, f"{where}.ordinal", _U16_MAX),
                iat_va=_uint(_field(imp, "iat", where), f"{where}.iat"),
            )
        )

    ops: dict[int, int] = {}
    for row in _parse_sparse((pkg / "operands.txt").read_text(encoding="utf-8")):
        if len(row) != 2:
            raise ValueError("layout operand row must have offset and value")
        ops[_uint(row[0], "operand offset")] = _uint(row[1], "operand value")
    calls: dict[int, tuple[int, int, int, int | None]] = {}
    for row in _parse_sparse((pkg / "calls.txt").read_text(encoding="utf-8")):
        if len(row) not in (4, 5):
            raise ValueError(
                "layout call row must have offset, rel32, prefix, suffix and optional opcode"
            )
        opcode = row[4] if len(row) == 5 else None
        if opcode is not None and opcode not in (0xE8, 0xE9):
            raise ValueError("layout call opcode must be E8 or E9")
        calls[_uint(row[0], "call offset")] = (
            _uint(row[1], "call rel32"),
            _uint(row[2], "call prefix", _U16_MAX),
            _uint(row[3], "call suffix", _U16_MAX),
            opcode,
        )

    stamp = _array(_field(lay, "export_stamp", "layout"), "layout.export_stamp")
    if len(stamp) != 2:
        raise ValueError("layout package layout.export_stamp must hold two integers")
    link_options = _array(_field(lay, "link_options", "layout"), "layout.link_options")
    header = blob("header.hex")
    try:
        _e, nsec, _optsz, _opt, _base = pe_header(header)
    except ValueError as exc:
        raise ValueError(f"layout package header.hex is not a PE32 header block: {exc}") from exc
    if nsec != len(sections):
        raise ValueError(
            f"layout package header.hex declares {nsec} sections but "
            f"rebrew-layout.toml lists {len(sections)}"
        )
    return LayoutMetadata(
        target=_string(_field(lay, "target", "layout"), "layout.target"),
        image_base=_uint(_field(lay, "image_base", "layout"), "layout.image_base"),
        link_options=[_string(o, "layout.link_options entry") for o in link_options],
        sections=sections,
        exports=[
            _table(e, "layout.exports entry")
            for e in _array(_field(lay, "exports", "layout"), "layout.exports")
        ],
        imports=imports,
        header=header,
        iat=blob("iat.hex"),
        prefix=blob("prefix.hex"),
        bookkeeping=blob("bookkeeping.hex"),
        data=blob("data.hex"),
        reloc=blob("reloc.hex"),
        operands=ops,
        calls=calls,
        exp_rva=_uint(lay.get("exp_rva", 0), "layout.exp_rva"),
        export_stamp=(
            _uint(stamp[0], "layout.export_stamp[0]"),
            _uint(stamp[1], "layout.export_stamp[1]"),
        ),
    )
