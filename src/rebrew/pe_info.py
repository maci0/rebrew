"""pe_info.py — read-only PE metadata dump via LIEF.

Reports the identity of a binary (format, arch, bits, image base, entry
point, subsystem, timestamp, checksum, size), the PE section table with
resolved read/write/execute protection flags, the DllCharacteristics
security flags plus the load-config-derived GS and SafeSEH state, the
Authenticode signature summary, the debug directory (CodeView PDB path,
GUID and age when LIEF exposes them), the Rich header (key and entries),
and the presence plus counts of the TLS directory, load config, resources,
relocations, exports, and imports.

ELF and Mach-O inputs return the identity block they share with PE plus a
note that the PE-only fields are unavailable, rather than an error.  Every
LIEF attribute access is guarded, since LIEF's Python API moves between
versions: an unavailable attribute is omitted from the payload instead of
crashing the command.  The payload carries no timestamp of the run, so two
runs over the same binary produce identical output.

Usage:
    rebrew pe-info [binary] [--json] [--target NAME]
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

import lief
import typer
from rich.console import Console
from rich.table import Table

from rebrew.binary_loader import detect_format_and_arch
from rebrew.cli import EXIT_ERROR, TargetOption, error_exit, json_print, require_config

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Named constants
# ---------------------------------------------------------------------------

# IMAGE_DLLCHARACTERISTICS bits (winnt.h).  Resolved from the raw dword so
# the output does not depend on a LIEF enum name surviving a version bump.
_DLL_HIGH_ENTROPY_VA = 0x0020
_DLL_DYNAMIC_BASE = 0x0040
_DLL_FORCE_INTEGRITY = 0x0080
_DLL_NX_COMPAT = 0x0100
_DLL_NO_ISOLATION = 0x0200
_DLL_NO_SEH = 0x0400
_DLL_GUARD_CF = 0x4000

# IMAGE_SCN_* section characteristic bits (winnt.h).
_SECTION_MEM_EXECUTE = 0x20000000
_SECTION_MEM_READ = 0x40000000
_SECTION_MEM_WRITE = 0x80000000

#: PE32+ optional-header magic (`IMAGE_NT_OPTIONAL_HDR64_MAGIC`).
_PE32_PLUS_MAGIC = 0x20B

#: Security flag key → human label, in the order ``flags_summary`` reports
#: them.  Only these keys reach the summary; ``certificate_table`` is a
#: presence fact, not a mitigation.
_SECURITY_FLAG_LABELS: tuple[tuple[str, str], ...] = (
    ("aslr", "ASLR"),
    ("nx", "DEP"),
    ("cfg", "CFG"),
    ("gs", "GS"),
    ("safe_seh", "SafeSEH"),
    ("seh", "SEH"),
    ("high_entropy_va", "HighEntropyVA"),
    ("force_integrity", "ForceIntegrity"),
    ("isolation", "Isolation"),
)

#: Presence flag key → LIEF ``has_*`` attribute.
_PRESENCE_ATTRS: tuple[tuple[str, str], ...] = (
    ("tls_directory", "has_tls"),
    ("load_config", "has_configuration"),
    ("resources", "has_resources"),
    ("relocations", "has_relocations"),
    ("exports", "has_exports"),
    ("imports", "has_imports"),
)

#: Keys of the payload rendered as nested tables rather than identity rows.
_STRUCTURED_KEYS = frozenset(
    {
        "note",
        "sections",
        "security_flags",
        "flags_summary",
        "authenticode",
        "debug",
        "rich_header",
        "presence",
        "counts",
    }
)

#: Non-PE note.  The same wording for every format, parameterized by name.
_PE_ONLY_NOTE = (
    "PE-only metadata (sections, security flags, Authenticode, debug, "
    "Rich header) is unavailable for {fmt} binaries"
)


# ---------------------------------------------------------------------------
# Guarded LIEF access
# ---------------------------------------------------------------------------


def _to_int(value: Any) -> int | None:
    """*value* as an int, or ``None`` when it is not integer-like."""
    if value is None or isinstance(value, bool):
        return int(value) if isinstance(value, bool) else None
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        inner = getattr(value, "value", None)
    if inner is not None:
        return _to_int(inner)
    return None


def _text(value: Any) -> str:
    """Display string for a LIEF name/enum: its ``name`` when it has one."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    name = getattr(value, "name", None)
    if isinstance(name, str):
        return name
    return str(value)


def _safe_list(obj: Any, attr: str) -> list[Any]:
    """``obj.attr`` as a list, or ``[]`` when it is missing or not iterable."""
    try:
        value = getattr(obj, attr, None)
    except (AttributeError, TypeError, ValueError, RuntimeError):
        return []
    if value is None:
        return []
    try:
        return list(value)
    except TypeError:
        return []


def _flag(value: Any) -> bool:
    """Truthiness of a LIEF boolean, false for a missing attribute."""
    return bool(value) if value is not None else False


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def pe_info(path: str | Path) -> dict[str, object]:
    """Metadata payload for the binary at *path*.

    Dispatches on the container format: PE gets the full header/section/
    security/debug/Rich dump; ELF and Mach-O get the shared identity block
    plus a note that the PE-only fields are unavailable.  Raises
    ``FileNotFoundError`` for a missing path and ``ValueError`` for an
    unparseable or unsupported file.
    """
    target = Path(path)
    if not target.exists():
        raise FileNotFoundError(f"Binary not found: {target}")

    fmt, arch = detect_format_and_arch(target)
    size = target.stat().st_size

    if fmt == "pe":
        pe = lief.PE.parse(str(target))
        if pe is None:
            raise ValueError(f"Failed to parse PE: {target}")
        return _pe_payload(pe, size, arch or "")

    if fmt == "elf":
        elf = lief.ELF.parse(str(target))
        if elf is None:
            raise ValueError(f"Failed to parse ELF: {target}")
        return _elf_payload(elf, size, arch or "")

    if fmt == "macho":
        macho = lief.MachO.parse(str(target))
        if macho is None:
            raise ValueError(f"Failed to parse Mach-O: {target}")
        return _macho_payload(macho, size, arch or "")

    raise ValueError(f"Unsupported binary format: {target}")


def _pe_payload(pe: Any, size: int, arch: str) -> dict[str, object]:
    """Full PE payload: identity, sections, security, debug, Rich, presence."""
    security = _security_flags(pe)
    payload: dict[str, object] = {
        **_pe_identity(pe, size, arch),
        "sections": _pe_sections(pe),
        "security_flags": security,
        "flags_summary": [
            label for key, label in _SECURITY_FLAG_LABELS if _flag(security.get(key))
        ],
        "authenticode": _authenticode(pe),
        "debug": _debug_entries(pe),
        "rich_header": _rich_header(pe),
        "presence": _presence(pe),
        "counts": _counts(pe),
    }
    return payload


def _pe_identity(pe: Any, size: int, arch: str) -> dict[str, object]:
    """PE identity block in the documented field order."""
    header = getattr(pe, "header", None)
    optional = getattr(pe, "optional_header", None)
    image_base = _to_int(getattr(optional, "imagebase", 0)) or 0
    entry_rva = _to_int(getattr(optional, "addressof_entrypoint", 0)) or 0
    timestamp = _to_int(getattr(header, "time_date_stamps", None))
    if timestamp is None:
        timestamp = _to_int(getattr(header, "time_date_stamp", None))
    checksum = _to_int(getattr(optional, "checksum", None))
    magic = getattr(optional, "magic", None)
    identity: dict[str, object] = {
        "format": "pe",
        "arch": arch,
        "bits": 64 if _is_pe32_plus(magic) else 32,
        "image_base": image_base,
        "entry_point": image_base + entry_rva,
    }
    subsystem = getattr(optional, "subsystem", None)
    if subsystem is not None:
        identity["subsystem"] = _text(subsystem)
    if timestamp is not None:
        identity["timestamp"] = timestamp
        iso = _timestamp_iso(timestamp)
        if iso is not None:
            identity["timestamp_iso"] = iso
    if checksum is not None:
        identity["checksum"] = checksum
    identity["size"] = size
    return identity


def _elf_payload(elf: Any, size: int, arch: str) -> dict[str, object]:
    """ELF identity block plus the note that PE-only fields do not apply."""
    header = getattr(elf, "header", None)
    identity: dict[str, object] = {
        "format": "elf",
        "arch": arch,
        "bits": _elf_bits(header),
        "image_base": _to_int(getattr(elf, "imagebase", 0)) or 0,
        "entry_point": _to_int(getattr(elf, "entrypoint", 0)) or 0,
        "size": size,
        "note": _PE_ONLY_NOTE.format(fmt="elf"),
    }
    return identity


def _macho_payload(macho: Any, size: int, arch: str) -> dict[str, object]:
    """Mach-O identity block plus the note that PE-only fields do not apply."""
    binary = macho.at(0) if isinstance(macho, lief.MachO.FatBinary) else macho
    header = getattr(binary, "header", None)
    identity: dict[str, object] = {
        "format": "macho",
        "arch": arch,
        "bits": _macho_bits(header),
        "image_base": _macho_image_base(binary),
        "entry_point": _to_int(getattr(binary, "entrypoint", 0)) or 0,
        "size": size,
        "note": _PE_ONLY_NOTE.format(fmt="macho"),
    }
    return identity


def _is_pe32_plus(magic: Any) -> bool:
    """True when the optional-header magic marks a PE32+ (64-bit) image."""
    if _text(magic) == "PE32_PLUS":
        return True
    return _to_int(magic) == _PE32_PLUS_MAGIC


def _elf_bits(header: Any) -> int | None:
    """32 or 64 from the ELF identity class, or ``None`` when unknown."""
    identity_class = getattr(header, "identity_class", None)
    name = _text(identity_class) if identity_class is not None else ""
    if name == "ELF64":
        return 64
    if name == "ELF32":
        return 32
    return None


def _macho_bits(header: Any) -> int | None:
    """32 or 64 from the Mach-O header, or ``None`` when unknown."""
    if _flag(getattr(header, "is_64bit", None)):
        return 64
    if _flag(getattr(header, "is_32bit", None)):
        return 32
    return None


def _macho_image_base(binary: Any) -> int:
    """Virtual address of the Mach-O ``__TEXT`` segment, else 0."""
    for segment in _safe_list(binary, "segments"):
        if _text(getattr(segment, "name", "")) == "__TEXT":
            return _to_int(getattr(segment, "virtual_address", 0)) or 0
    return 0


def _timestamp_iso(timestamp: int) -> str | None:
    """UTC ISO-8601 rendering of a PE timestamp, or ``None`` when implausible.

    Derives only from the value already in the file, so it stays
    deterministic; ``0`` (unstamped) and out-of-range values are omitted
    rather than rendered as a bogus 1970 date.
    """
    if timestamp <= 0:
        return None
    try:
        moment = datetime.datetime.fromtimestamp(timestamp, datetime.UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.isoformat().replace("+00:00", "Z")


def _pe_sections(pe: Any) -> list[dict[str, object]]:
    """Section table in file order, protections resolved from characteristics."""
    sections: list[dict[str, object]] = []
    for section in _safe_list(pe, "sections"):
        characteristics = _to_int(getattr(section, "characteristics", 0)) or 0
        sections.append(
            {
                "name": _text(getattr(section, "name", "")),
                "virtual_address": _to_int(getattr(section, "virtual_address", 0)) or 0,
                "virtual_size": _to_int(getattr(section, "virtual_size", 0)) or 0,
                "raw_size": _to_int(getattr(section, "sizeof_raw_data", 0)) or 0,
                "raw_offset": _to_int(getattr(section, "pointerto_raw_data", 0)) or 0,
                "read": bool(characteristics & _SECTION_MEM_READ),
                "write": bool(characteristics & _SECTION_MEM_WRITE),
                "execute": bool(characteristics & _SECTION_MEM_EXECUTE),
            }
        )
    return sections


def _load_config(pe: Any) -> Any | None:
    """The PE load-configuration structure, or ``None``.

    Reads the structure directly rather than gating on ``has_configuration``:
    a LIEF version that exposes the structure but not the boolean would
    otherwise report GS and SafeSEH as absent.
    """
    config = getattr(pe, "load_configuration", None)
    return config if config is not None else None


def _security_flags(pe: Any) -> dict[str, object]:
    """DllCharacteristics mitigations plus the load-config GS/SafeSEH facts.

    Every entry is a boolean except ``dll_characteristics`` (the raw dword)
    and ``certificate_table`` (a data-directory presence fact).
    """
    optional = getattr(pe, "optional_header", None)
    dllc = _to_int(getattr(optional, "dll_characteristics", 0)) or 0
    config = _load_config(pe)
    gs = config is not None and _to_int(getattr(config, "security_cookie", 0)) not in (None, 0)
    safe_seh = config is not None and _to_int(getattr(config, "se_handler_table", 0)) not in (
        None,
        0,
    )
    return {
        "dll_characteristics": dllc,
        "aslr": bool(dllc & _DLL_DYNAMIC_BASE),
        "nx": bool(dllc & _DLL_NX_COMPAT),
        "cfg": bool(dllc & _DLL_GUARD_CF),
        "gs": gs,
        "safe_seh": safe_seh,
        "seh": not (dllc & _DLL_NO_SEH),
        "high_entropy_va": bool(dllc & _DLL_HIGH_ENTROPY_VA),
        "force_integrity": bool(dllc & _DLL_FORCE_INTEGRITY),
        "isolation": not (dllc & _DLL_NO_ISOLATION),
        "certificate_table": _certificate_table_present(pe),
    }


def _certificate_table_present(pe: Any) -> bool:
    """True when the certificate data-directory entry is non-empty."""
    for directory in _safe_list(pe, "data_directories"):
        if _text(getattr(directory, "type", "")) == "CERTIFICATE_TABLE":
            return (_to_int(getattr(directory, "size", 0)) or 0) > 0
    return False


def _authenticode(pe: Any) -> dict[str, object]:
    """Authenticode presence, signature count, and signer names."""
    signatures = _safe_list(pe, "signatures")
    signers: list[str] = []
    for signature in signatures:
        for signer in _safe_list(signature, "signers"):
            name = getattr(signer, "name", None)
            if isinstance(name, str) and name:
                signers.append(name)
    return {
        "present": bool(signatures) or _certificate_table_present(pe),
        "signature_count": len(signatures),
        "signers": list(dict.fromkeys(signers)),
    }


def _debug_entries(pe: Any) -> list[dict[str, object]]:
    """Debug directory entries; CodeView fields appear only when exposed."""
    entries: list[dict[str, object]] = []
    for entry in _safe_list(pe, "debug"):
        item: dict[str, object] = {"type": _text(getattr(entry, "type", "UNKNOWN"))}
        pdb_path = getattr(entry, "pdb_path", None)
        if isinstance(pdb_path, str) and pdb_path:
            item["pdb_path"] = pdb_path
        guid = _render_guid(getattr(entry, "guid", None))
        if guid:
            item["guid"] = guid
        age = _to_int(getattr(entry, "age", None))
        if age is not None:
            item["age"] = age
        entries.append(item)
    return entries


def _render_guid(value: Any) -> str | None:
    """Canonical hex rendering of a CodeView GUID, or ``None``.

    LIEF has exposed the GUID as a string, a bytes object, and a 16-int
    sequence across versions; the sequence form is rendered straight through
    as bytes, which is stable regardless of field byte order.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    if isinstance(value, bytes):
        return value.hex() or None
    try:
        octets = [int(item) for item in value]
    except (TypeError, ValueError):
        return None
    if len(octets) != 16:
        return None
    return "".join(f"{octet & 0xFF:02x}" for octet in octets)


def _rich_header(pe: Any) -> dict[str, object]:
    """Rich-header presence, XOR key, and decoded entries.

    LIEF exposes the key and the ``(id, build_id, count)`` entries directly;
    ``present`` is a real fact, so it is always reported, while ``key`` and
    ``entries`` appear only when LIEF parsed them.
    """
    rich = getattr(pe, "rich_header", None)
    present = rich is not None or _flag(getattr(pe, "has_rich_header", None))
    payload: dict[str, object] = {"present": present}
    if rich is None:
        return payload
    key = _to_int(getattr(rich, "key", None))
    if key is not None:
        payload["key"] = key
    entries: list[dict[str, int]] = []
    for entry in _safe_list(rich, "entries"):
        entry_id = _to_int(getattr(entry, "id", None))
        build_id = _to_int(getattr(entry, "build_id", None))
        count = _to_int(getattr(entry, "count", None))
        if entry_id is None or build_id is None or count is None:
            continue
        entries.append({"id": entry_id, "build_id": build_id, "count": count})
    if entries:
        payload["entries"] = entries
    return payload


def _presence(pe: Any) -> dict[str, bool]:
    """Presence of the TLS, load-config, resource, reloc, export, import dirs."""
    present = {key: _flag(getattr(pe, attr, None)) for key, attr in _PRESENCE_ATTRS}
    if _load_config(pe) is not None:
        present["load_config"] = True
    return present


def _counts(pe: Any) -> dict[str, int]:
    """Cheap directory counts: exports, imports, import DLLs, relocations."""
    return {
        "exports": len(_safe_list(pe, "exported_functions")),
        "imports": sum(len(_safe_list(module, "entries")) for module in _safe_list(pe, "imports")),
        "import_dlls": len(_safe_list(pe, "imports")),
        "relocations": len(_safe_list(pe, "relocations")),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _hex(value: object) -> str:
    """Hex rendering for an address-sized int, else ``str(value)``."""
    return (
        f"0x{value:08x}" if isinstance(value, int) and not isinstance(value, bool) else str(value)
    )


def _print_human(info: dict[str, object], binary: Path) -> None:
    """Render the payload as Rich tables on stderr."""
    identity = Table(title=f"PE info: {binary}")
    identity.add_column("Field", style="bold")
    identity.add_column("Value", overflow="fold")
    for key, value in info.items():
        if key in _STRUCTURED_KEYS:
            continue
        rendered = _hex(value) if key in ("image_base", "entry_point") else str(value)
        identity.add_row(key, rendered)
    console.print(identity)

    note = info.get("note")
    if isinstance(note, str):
        console.print(f"[dim]{note}[/dim]")

    sections = info.get("sections")
    if isinstance(sections, list) and sections:
        table = Table(title="Sections")
        table.add_column("Name")
        table.add_column("VA", justify="right")
        table.add_column("VSize", justify="right")
        table.add_column("RawSize", justify="right")
        table.add_column("RawOff", justify="right")
        table.add_column("Prot")
        for section in sections:
            if not isinstance(section, dict):
                continue
            table.add_row(
                str(section.get("name", "")),
                _hex(section.get("virtual_address")),
                str(section.get("virtual_size")),
                str(section.get("raw_size")),
                _hex(section.get("raw_offset")),
                _protection_text(section),
            )
        console.print(table)

    security = info.get("security_flags")
    if isinstance(security, dict):
        table = Table(title="Security flags")
        table.add_column("Flag", style="bold")
        table.add_column("Value", justify="right")
        for key, value in security.items():
            if key == "dll_characteristics":
                table.add_row(key, f"0x{int(value):04x}" if isinstance(value, int) else str(value))
            else:
                table.add_row(key, "[green]yes[/green]" if value else "[dim]no[/dim]")
        console.print(table)
        summary = info.get("flags_summary")
        if isinstance(summary, list):
            console.print(f"flags_summary: {', '.join(str(item) for item in summary) or '(none)'}")

    debug = info.get("debug")
    if isinstance(debug, list) and debug:
        table = Table(title="Debug")
        table.add_column("Type")
        table.add_column("PDB path", overflow="fold")
        table.add_column("GUID")
        table.add_column("Age", justify="right")
        for entry in debug:
            if not isinstance(entry, dict):
                continue
            table.add_row(
                str(entry.get("type", "")),
                str(entry.get("pdb_path", "")),
                str(entry.get("guid", "")),
                str(entry.get("age", "")),
            )
        console.print(table)

    rich = info.get("rich_header")
    if isinstance(rich, dict) and rich.get("present"):
        entries = rich.get("entries")
        if isinstance(entries, list):
            table = Table(title="Rich header")
            table.add_column("Id", justify="right")
            table.add_column("Build", justify="right")
            table.add_column("Count", justify="right")
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                table.add_row(
                    str(entry.get("id")), str(entry.get("build_id")), str(entry.get("count"))
                )
            rich_key = rich.get("key")
            if isinstance(rich_key, int):
                console.print(f"Rich key: 0x{rich_key:08x}")
            console.print(table)


def _protection_text(section: dict[str, object]) -> str:
    """``rwx`` style protection string from the section's boolean flags."""
    return "".join(
        (
            "r" if section.get("read") else "-",
            "w" if section.get("write") else "-",
            "x" if section.get("execute") else "-",
        )
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Dump PE metadata: identity, sections, security flags, debug, Rich header.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew pe-info · · · · · · · Dump the project's target binary\n\n"
        "  rebrew pe-info game.exe · · Dump a specific binary\n\n"
        "  rebrew pe-info game.exe --json · Machine-readable payload\n\n"
        "[dim]ELF and Mach-O inputs report the shared identity fields and a "
        "note that the PE-only metadata is unavailable.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    binary: Path | None = typer.Argument(None, help="Binary path (default: project target)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Dump PE metadata: identity, sections, security flags, debug, Rich header."""
    if binary is None:
        cfg = require_config(target=target, json_mode=json_output)
        binary = Path(cfg.target_binary)
        if not binary.exists():
            error_exit(f"target binary missing: {binary}", json_mode=json_output, code=EXIT_ERROR)
    if not binary.exists():
        error_exit(f"binary not found: {binary}", json_mode=json_output)

    try:
        info = pe_info(binary)
    except FileNotFoundError as exc:
        error_exit(str(exc), json_mode=json_output)
    except (OSError, ValueError) as exc:
        error_exit(f"cannot inspect {binary}: {exc}", json_mode=json_output, code=EXIT_ERROR)

    if json_output:
        json_print(info)
        return
    _print_human(info, binary)


def main_entry() -> None:
    """Run the Typer CLI application."""
    _standalone = typer.Typer()
    _standalone.command()(main)
    _standalone()


if __name__ == "__main__":
    main_entry()
