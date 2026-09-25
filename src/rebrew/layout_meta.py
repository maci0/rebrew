"""layout_meta.py — text-only layout metadata for byte-identical post-linking.

The MSVC6 linker cannot be made to reproduce the reference's import-record
placement, ``.data`` COMDAT order, ``.reloc`` set, or toolchain-stamped PE
header, so ``rebrew postlink`` converges the built binary onto the
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
    suffix) for every E8/E9 relative call/jump in the reference.  The
    fixer rewrites only where the built differs and the instruction
    context matches, exactly like the old byte-scan did.

All files are plain text (``#`` comment lines allowed in the hex dumps);
``extract_layout`` derives the package from a binary, ``write_package`` /
``load_package`` serialize it.  ``gen-layout`` emits it during intake;
``postlink --layout <dir>`` consumes it, so the original DLL never needs
to be present at build time.
"""

from __future__ import annotations

import dataclasses
import struct
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rebrew.pe_headers import pe_lfanew, sections_at

#: Cap on import name-table / descriptor slots read from one PE.  A missing
#: null terminator would otherwise walk past EOF into ``struct.error``.
_MAX_IMPORT_SLOTS = 65536

#: Cap on export AddressOfFunctions / AddressOfNames entries.  A forged
#: NumberOfNames/NumberOfFunctions of ``0xFFFFFFFF`` would otherwise hang in
#: ``range()`` or raise ``struct.error`` past EOF.
_MAX_EXPORT_ENTRIES = 65536


@dataclasses.dataclass
class SectionMeta:
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
    calls: dict[int, tuple[int, int, int]]  # .text-relative off → (rel32, prefix2, suffix2)
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
    truth, not a TOML block in rebrew-project.toml.
    """
    import tomllib

    txt = Path(root) / "layout" / target / "rebrew-layout.toml"
    try:
        raw = tomllib.loads(txt.read_text(encoding="utf-8-sig"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(
            f"no layout package at {txt} (run rebrew gen-layout first): {exc}"
        ) from exc
    lay = raw.get("layout", {})
    base = int(lay.get("image_base", 0) or 0)
    for s in lay.get("sections", []):
        if s.get("name") == ".data":
            va, raw_sz, vs = int(s["va"]), int(s["raw"]), int(s["vs"])
            return base + va, base + va + raw_sz, base + va + vs
    raise ValueError(f"no .data section in {txt} (run rebrew gen-layout first)")


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
        if txt.stat().st_mtime_ns < bin_path.stat().st_mtime_ns:
            return None  # binary rebuilt after gen-layout — parse it instead
        lay = tomllib.loads(txt.read_text(encoding="utf-8-sig"))["layout"]
        base = int(lay.get("image_base", 0) or 0)
        sections: list[tuple[str, int, int, int, int]] = []
        text_va = text_size = text_raw = 0
        for s in lay.get("sections", []):
            name = str(s.get("name") or "")
            va = base + int(s.get("va", 0) or 0)
            rec = (
                name,
                va,
                int(s.get("vs", 0) or 0),
                int(s.get("raw", 0) or 0),
                int(s.get("ptr", 0) or 0),
            )
            sections.append(rec)
            if name == ".text":
                text_va, text_size, text_raw = rec[1], rec[2], rec[4]
    except (OSError, KeyError, TypeError, ValueError, tomllib.TOMLDecodeError):
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


def parse_pe(data: bytes) -> tuple[int, int, int, int, int]:
    """Return (e_lfanew, nsec, optsz, opt_off, image_base) with sanity checks."""
    if len(data) < 0x40:
        raise ValueError("file too small to be a PE")
    e = pe_lfanew(data)
    if e is None or e + 24 > len(data):
        raise ValueError("no PE signature")
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    optsz = struct.unpack_from("<H", data, e + 20)[0]
    opt = e + 24
    # image_base is at optional+28.  A SizeOfOptionalHeader shorter than that,
    # on a file that ends at the claim, used to raise struct.error here.
    if opt + optsz > len(data) or opt + 32 > len(data):
        raise ValueError("truncated optional header")
    if opt + optsz + 40 * nsec > len(data):
        raise ValueError("truncated section table")
    if struct.unpack_from("<H", data, opt)[0] != 0x10B:
        raise ValueError("PE32+ not supported")
    image_base = struct.unpack_from("<I", data, opt + 28)[0]
    return e, nsec, optsz, opt, image_base


def _data_dir(data: bytes, opt: int, index: int) -> tuple[int, int]:
    """Data directory *index*, or ``ValueError`` when it lies past EOF.

    Index 12 (IAT) is the deepest directory ``extract_layout`` reads.  A PE32
    whose optional header is present but shorter than that directory used to
    raise ``struct.error``, which ``gen-layout`` does not catch.
    """
    off = opt + 96 + 8 * index
    if off + 8 > len(data):
        raise ValueError("truncated optional header")
    return struct.unpack_from("<II", data, off)


def extract_layout(data: bytes, target: str = "") -> LayoutMetadata:
    """Derive the full text-only layout metadata from a reference binary."""
    e, nsec, optsz, opt, image_base = parse_pe(data)
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
        rblob = data[reloc_sec.raw_ptr : reloc_sec.raw_ptr + reloc_sec.raw]
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

    calls: dict[int, tuple[int, int, int]] = {}
    # i reads tb[i+4:i+6]; the last suffix ends at len(tb)-6.
    for i in range(3, len(tb) - 5):
        if tb[i - 1] in (0xE8, 0xE9):
            rel32 = struct.unpack_from("<I", tb, i)[0]
            pre = int.from_bytes(tb[i - 3 : i - 1], "big")
            suf = int.from_bytes(tb[i + 4 : i + 6], "big")
            calls[i] = (rel32, pre, suf)

    # export directory Characteristics+TimeDateStamp pair
    export_stamp = (0, 0)
    if exp_rva:
        eo = off(exp_rva)
        if eo is not None and eo + 8 <= len(data):
            export_stamp = struct.unpack_from("<II", data, eo)

    # imports with reference IAT slot VAs
    imports: list[ImportMeta] = []
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
        out.append(tuple(int(x, 0) for x in line.split()))
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
        head = f"# {meta.target} - {name}: {len(blob)} bytes\n# generated by rebrew gen-layout; do not hand-edit\n"
        p.write_text(head + blob.hex("\n", -32) + "\n", encoding="utf-8")
        written.append(p)

    ops = sorted(meta.operands.items())
    p = out_dir / "operands.txt"
    p.write_text(
        f"# {meta.target} - .text data-operand map: '.text-relative-offset value'\n"
        "# generated by rebrew gen-layout; do not hand-edit\n"
        + _sparse_lines([(o, v) for o, v in ops]),
        encoding="utf-8",
    )
    written.append(p)

    calls = sorted(meta.calls.items())
    p = out_dir / "calls.txt"
    p.write_text(
        f"# {meta.target} - .text E8/E9 map: '.text-relative-offset rel32 prefix2 suffix2'\n"
        "# generated by rebrew gen-layout; do not hand-edit\n"
        + _sparse_lines([(o, r, pre, suf) for o, (r, pre, suf) in calls]),
        encoding="utf-8",
    )
    written.append(p)

    p = out_dir / "rebrew-layout.toml"
    p.write_text(fmt_toml(meta), encoding="utf-8")
    written.append(p)
    return written


def load_package(pkg_dir: Path) -> LayoutMetadata:
    """Load a text-only layout package written by :func:`write_package`."""
    import tomlkit

    pkg = Path(pkg_dir)
    if not (pkg / "rebrew-layout.toml").exists():
        raise ValueError(
            f"layout package {pkg} is missing rebrew-layout.toml — expected the text "
            "package from 'rebrew gen-layout' (layout/<target>/), not a binary"
        )

    def blob(name: str) -> bytes:
        p = pkg / name
        if not p.exists():
            raise ValueError(f"layout package missing {name} (run 'rebrew gen-layout')")
        return _from_hex(p.read_text(encoding="utf-8"))

    structured: Any = tomlkit.parse((pkg / "rebrew-layout.toml").read_text(encoding="utf-8-sig"))
    lay: Any = structured["layout"]

    sections = [
        SectionMeta(
            name=s["name"], va=s["va"], vs=s["vs"], raw=s["raw"], raw_ptr=s["ptr"], chars=s["chars"]
        )
        for s in lay["sections"]
    ]

    imports = [
        ImportMeta(dll=i["dll"], name=i.get("name"), ordinal=i.get("ordinal"), iat_va=i["iat"])
        for i in lay["imports"]
    ]

    ops: dict[int, int] = {}
    for o, v in _parse_sparse((pkg / "operands.txt").read_text(encoding="utf-8")):
        ops[o] = v
    calls: dict[int, tuple[int, int, int]] = {}
    for o, r, pre, suf in _parse_sparse((pkg / "calls.txt").read_text(encoding="utf-8")):
        calls[o] = (r, pre, suf)

    stamp = tuple(lay["export_stamp"])
    return LayoutMetadata(
        target=lay["target"],
        image_base=lay["image_base"],
        link_options=list(lay["link_options"]),
        sections=sections,
        exports=list(lay["exports"]),
        imports=imports,
        header=blob("header.hex"),
        iat=blob("iat.hex"),
        prefix=blob("prefix.hex"),
        bookkeeping=blob("bookkeeping.hex"),
        data=blob("data.hex"),
        reloc=blob("reloc.hex"),
        operands=ops,
        calls=calls,
        exp_rva=int(lay.get("exp_rva", 0)),
        export_stamp=(int(stamp[0]), int(stamp[1])),
    )
