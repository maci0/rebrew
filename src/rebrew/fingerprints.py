"""fingerprints.py: Content fingerprint bundle for a target binary.

Derives the hashes and layout signatures that identify a binary build:
streamed file digests (MD5 / SHA1 / SHA256 / CRC32), the Mandiant import
hash, the MSVC Rich-header hash, per-section Shannon entropy, and, when a
backend is importable, TLSH / ssdeep fuzzy hashes.  Everything comes from
the raw file plus LIEF's PE import table, so the same binary yields the
same bundle on any machine.

LIEF's ``RichHeader`` splits the comp-id dword into ``id`` / ``build_id``
and does not expose the on-disk XORed pair, so the Rich header is decoded
from the DOS stub and re-encoded through :func:`rich_header_bytes_from_parts`
to pin the byte layout the hash covers.

Usage:
    rebrew fingerprints [binary]
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import math
import struct
import zlib
from collections.abc import Iterable
from pathlib import Path
from typing import Any, cast

import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import EXIT_ERROR, TargetOption, error_exit, json_print, require_config

console = Console(stderr=True)

#: Stream chunk for :func:`file_hashes`: the file is read in these slices
#: so a large binary never lands in memory as one object.
_CHUNK_SIZE = 1 << 20

#: Section of the PE DOS stub scanned for the Rich header markers.
_DOS_STUB_SCAN = 0x400

#: Bytes of the canonical Rich header between ``DanS`` and the first entry
#: (three padding dwords).
_RICH_PADDING = 12


def file_hashes(path: str | Path) -> dict[str, str]:
    """Return ``md5`` / ``sha1`` / ``sha256`` / ``crc32`` for *path*.

    The file is streamed once in :data:`_CHUNK_SIZE` chunks, feeding all
    four digests.  ``crc32`` is the zlib CRC-32 rendered as 8 lowercase hex
    digits.  Raises ``FileNotFoundError`` when *path* does not exist.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    crc = 0
    with Path(path).open("rb") as f:
        while chunk := f.read(_CHUNK_SIZE):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            crc = zlib.crc32(chunk, crc)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "crc32": f"{crc & 0xFFFFFFFF:08x}",
    }


def imphash_from_pairs(pairs: Iterable[tuple[str, str]]) -> str:
    """Mandiant import hash over ``(dll, name)`` pairs.

    Each record is ``<dll-basename>.<name>``: the DLL basename before its
    first dot, lowercased, and the function name lowercased.  Records keep
    the input order and are joined with ``,``; ordinal imports pass the name
    as ``ord<N>``.  Callers pass a non-empty iterable: :func:`imphash`
    returns ``None`` for a binary without imports rather than hashing an
    empty record list.
    """
    records = [f"{dll.split('.', 1)[0].lower()}.{name.lower()}" for dll, name in pairs]
    return hashlib.md5(",".join(records).encode("utf-8")).hexdigest()


def imphash(path: str | Path) -> str | None:
    """Mandiant import hash of a PE, or ``None``.

    Parses the import table directly (LIEF) instead of
    :func:`rebrew.imports.parse_imports`, which drops ordinal imports:
    every entry keeps its declaration order and ordinals become
    ``dll.ord<N>``.  Returns ``None`` for a missing, non-PE, unparseable,
    or import-less binary.
    """
    p = Path(path)
    if not p.exists():
        return None
    import lief

    try:
        if not lief.is_pe(str(p)):
            return None
        pe = lief.PE.parse(str(p))
    except Exception:
        return None
    if pe is None:
        return None
    pairs: list[tuple[str, str]] = []
    for entry in pe.imports:
        dll = str(entry.name)
        for fn in entry.entries:
            name = str(fn.name)
            if not name:
                ordinal = int(fn.ordinal)
                if ordinal == 0:
                    continue
                name = f"ord{ordinal}"
            pairs.append((dll, name))
    if not pairs:
        return None
    return imphash_from_pairs(pairs)


def rich_header_bytes_from_parts(key: int, entries: Iterable[tuple[int, int]]) -> bytes:
    """Canonical Rich-header bytes for *key* and ``(comp_id, count)`` *entries*.

    Layout: ``DanS`` + three zero padding dwords + one little-endian
    ``comp_id ^ key`` / ``count ^ key`` pair per entry + ``Rich`` + the key
    as a little-endian uint32.  The 12 padding bytes are canonical zeros;
    the on-disk form stores them XORed with the key and they carry no data.
    """
    body = bytearray(b"DanS")
    body += b"\x00" * _RICH_PADDING
    for comp_id, count in entries:
        body += struct.pack("<II", comp_id ^ key, count ^ key)
    body += b"Rich"
    body += struct.pack("<I", key)
    return bytes(body)


def rich_header_hash_from_parts(key: int, entries: Iterable[tuple[int, int]]) -> str:
    """MD5 of :func:`rich_header_bytes_from_parts`."""
    return hashlib.md5(rich_header_bytes_from_parts(key, entries)).hexdigest()


def _rich_header_parts_from_dos_stub(data: bytes) -> tuple[int, list[tuple[int, int]]] | None:
    """Decode the Rich header in a DOS stub, or ``None``.

    Finds ``Rich``, reads the following uint32 as the XOR key, then decodes
    the ``comp_id`` / ``count`` pairs between the preceding ``DanS`` and the
    ``Rich`` marker.
    """
    pos = data.find(b"Rich")
    while pos != -1:
        key_off = pos + 4
        if key_off + 4 <= len(data):
            key = int.from_bytes(data[key_off : key_off + 4], "little")
            dans = data.rfind(b"DanS", 0, pos)
            if dans != -1:
                body = data[dans + 4 + _RICH_PADDING : pos]
                if body and len(body) % 8 == 0:
                    entries = [
                        (
                            int.from_bytes(body[i : i + 4], "little") ^ key,
                            int.from_bytes(body[i + 4 : i + 8], "little") ^ key,
                        )
                        for i in range(0, len(body), 8)
                    ]
                    return key, entries
        pos = data.find(b"Rich", pos + 1)
    return None


def rich_header_hash(path: str | Path) -> str | None:
    """MD5 of the binary's canonical Rich header, or ``None`` when absent.

    Scans the first :data:`_DOS_STUB_SCAN` bytes of the DOS stub.  Returns
    ``None`` for a missing file, a non-PE, or a binary whose linker wrote no
    Rich header.
    """
    p = Path(path)
    if not p.exists():
        return None
    try:
        with p.open("rb") as f:
            head = f.read(_DOS_STUB_SCAN)
    except OSError:
        return None
    parts = _rich_header_parts_from_dos_stub(head)
    if parts is None:
        return None
    key, entries = parts
    return rich_header_hash_from_parts(key, entries)


def function_boundaries_hash(functions: Iterable[tuple[int, int]]) -> str:
    """SHA-256 over ``(va, size)`` function boundaries.

    Records are ``<va:08x>:<size:x>`` joined with newlines after sorting by
    VA, so the same function set hashes identically regardless of input
    order, and a changed size or VA changes the hash.
    """
    lines = "\n".join(f"{va:08x}:{size:x}" for va, size in sorted(functions))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy of *data* in bits per byte (0.0 for empty input)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def section_entropies(path: str | Path) -> list[dict[str, object]]:
    """Per-section ``name`` / ``va`` / ``vsize`` / ``raw_size`` / ``entropy``.

    Entropy is Shannon entropy over the section's raw file bytes, rounded to
    4 decimals.  Sections appear in file order.  Returns ``[]`` when the
    binary cannot be parsed.
    """
    p = Path(path)
    if not p.exists():
        return []
    from rebrew.binary_loader import load_binary

    try:
        info = load_binary(p)
        raw = info.data
    except Exception:
        return []
    out: list[dict[str, object]] = []
    for name, section in info.sections.items():
        start = section.file_offset
        end = min(start + section.raw_size, len(raw))
        chunk = raw[start:end] if 0 <= start < end else b""
        out.append(
            {
                "name": name,
                "va": section.va,
                "vsize": section.size,
                "raw_size": section.raw_size,
                "entropy": round(_shannon_entropy(chunk), 4),
            }
        )
    return out


def _optional_backend(module: str) -> Any | None:
    """Import *module* when it is installed, else ``None``.

    TLSH and ssdeep are optional; a missing backend leaves its key out of
    the fingerprint bundle instead of failing the run.
    """
    try:
        if importlib.util.find_spec(module) is None:
            return None
        return importlib.import_module(module)
    except (ImportError, ValueError):
        return None


def _fuzzy_hashes(path: Path) -> dict[str, str | None]:
    """TLSH / ssdeep hashes for *path*, keyed only for importable backends."""
    tlsh_mod = _optional_backend("tlsh")
    ssdeep_mod = _optional_backend("ppdeep")
    if tlsh_mod is None and ssdeep_mod is None:
        return {}
    try:
        raw = path.read_bytes()
    except OSError:
        return {}
    out: dict[str, str | None] = {}
    if tlsh_mod is not None:
        out["tlsh"] = _backend_hash(tlsh_mod, raw)
    if ssdeep_mod is not None:
        out["ssdeep"] = _backend_hash(ssdeep_mod, raw)
    return out


def _backend_hash(backend: Any, data: bytes) -> str | None:
    """Run a fuzzy-hash backend's ``hash`` over *data*, or ``None``.

    TLSH rejects inputs below its minimum length, so a failure degrades the
    field to ``None`` rather than aborting the bundle.
    """
    try:
        return cast(str, backend.hash(data))
    except Exception:
        return None


def fingerprint_bundle(path: str | Path) -> dict[str, object]:
    """Fingerprint bundle for *path*.

    Carries ``md5`` / ``sha1`` / ``sha256`` / ``crc32`` (from
    :func:`file_hashes`), ``format`` / ``arch`` (from
    :func:`rebrew.binary_loader.detect_format_and_arch`), ``size``,
    ``imphash``, ``rich_header_hash``, and ``section_entropies``.  The
    ``tlsh`` / ``ssdeep`` keys appear only when their backend is importable.
    A field that cannot be derived (unknown format, no imports, no Rich
    header) is ``None``; only a missing path raises, as
    ``FileNotFoundError``.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Binary not found: {p}")

    from rebrew.binary_loader import detect_format_and_arch

    try:
        fmt, arch = detect_format_and_arch(p)
    except (OSError, ValueError):
        fmt, arch = None, None

    bundle: dict[str, object] = {
        **file_hashes(p),
        "format": fmt,
        "arch": arch,
        "size": p.stat().st_size,
        "imphash": imphash(p),
        "rich_header_hash": rich_header_hash(p),
        "section_entropies": section_entropies(p),
    }
    bundle.update(_fuzzy_hashes(p))
    return bundle


app = typer.Typer(
    help="Fingerprint a binary: file hashes, imphash, Rich-header hash, section entropy.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew fingerprints · · · · · · · · · Fingerprint the project's target binary\n\n"
        "  rebrew fingerprints original/game.exe · Fingerprint a specific binary\n\n"
        "  rebrew fingerprints game.exe --json · · Machine-readable bundle\n\n"
        "[bold]What it shows:[/bold]\n\n"
        "  File hashes · · · · · · · · MD5 / SHA1 / SHA256 / CRC32 of the raw file\n\n"
        "  imphash · · · · · · · · · · Mandiant import hash (DLL.API order)\n\n"
        "  rich_header_hash · · · · · MD5 of the MSVC Rich header (toolchain stamp)\n\n"
        "  Section entropy · · · · · · Per-section Shannon entropy over raw bytes\n\n"
        "[dim]TLSH and ssdeep are reported only when their optional backend "
        "is installed.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    binary: Path | None = typer.Argument(None, help="Binary path (default: project target)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Fingerprint a binary: hashes, imphash, Rich-header hash, section entropy."""
    if binary is None:
        cfg = require_config(target=target, json_mode=json_output)
        binary = cfg.target_binary
        if not binary.exists():
            error_exit(f"target binary missing: {binary}", json_mode=json_output, code=EXIT_ERROR)
    if not binary.exists():
        error_exit(f"binary not found: {binary}", json_mode=json_output)

    try:
        bundle = fingerprint_bundle(binary)
    except OSError as exc:
        error_exit(f"cannot fingerprint {binary}: {exc}", json_mode=json_output, code=EXIT_ERROR)

    if json_output:
        json_print(bundle)
        return

    table = Table(title=f"Fingerprint: {binary}")
    table.add_column("Field", style="bold")
    table.add_column("Value", overflow="fold")
    for key, value in bundle.items():
        if key == "section_entropies":
            continue
        table.add_row(key, _format_value(value))
    console.print(table)

    sections = cast(list[dict[str, object]], bundle["section_entropies"])
    if sections:
        section_table = Table(title="Sections")
        section_table.add_column("Name")
        section_table.add_column("VA")
        section_table.add_column("VSize", justify="right")
        section_table.add_column("RawSize", justify="right")
        section_table.add_column("Entropy", justify="right")
        for section in sections:
            va = section["va"]
            va_text = f"0x{va:08x}" if isinstance(va, int) else str(va)
            section_table.add_row(
                str(section["name"]),
                va_text,
                str(section["vsize"]),
                str(section["raw_size"]),
                f"{float(cast(float, section['entropy'])):.4f}",
            )
        console.print(section_table)


def _format_value(value: object) -> str:
    """Render a bundle value for the human table (``None`` as ``-``)."""
    if value is None:
        return "-"
    if isinstance(value, int) and not isinstance(value, bool):
        return f"{value:,}"
    return str(value)


def main_entry() -> None:
    """Run the Typer CLI application."""
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
