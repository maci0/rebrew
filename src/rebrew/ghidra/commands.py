"""ReVa MCP command builder for Ghidra integration.

Constructs MCP commands and orchestrates Ghidra sync operations, including
command building for push operations and direct MCP communication for pull
operations.
"""

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rebrew.catalog import RegistryEntry
import httpx
from rich.console import Console

from rebrew.config import ProjectConfig
from rebrew.ghidra.client import (
    fetch_mcp_tool_raw,
    init_mcp_session,
)
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

# Pattern matching generic auto-names that shouldn't overwrite Ghidra renames
_GENERIC_NAME_RE = re.compile(r"^_?(func_|FUN_)[0-9a-fA-F]+(@\d+)?$")

# Matches non-identifier characters to remove from symbol names.
_NORMALIZE_NAME_RE = re.compile(r"[^A-Za-z0-9_]")

# Status → bookmark category prefix for visual distinction
_STATUS_BOOKMARK_CATEGORY = {
    "EXACT": "rebrew/exact",
    "RELOC": "rebrew/reloc",
    "NEAR_MATCHING": "rebrew/matching",
    "STUB": "rebrew/stub",
}


def _bookmark_cmd(program_path: str, va_hex: str, category: str, comment: str) -> dict[str, Any]:
    """Build a ``set-bookmark`` MCP command (always of Ghidra type ``Note``)."""
    return {
        "tool": "set-bookmark",
        "args": {
            "programPath": program_path,
            "addressOrSymbol": va_hex,
            "type": "Note",
            "category": category,
            "comment": comment,
        },
    }


def build_bookmark_commands(
    entries: list[dict[str, Any]], program_path: str
) -> list[dict[str, Any]]:
    """``set-bookmark`` ops for annotated functions with a match status.

    The MCP structural-op counterpart to the BinSync field sync: bookmarks
    are not expressible in the state dir, so they stay on MCP
    (metadata-review R1).
    """
    out: list[dict[str, Any]] = []
    for e in entries:
        if e.get("marker_type") in ("DATA", "GLOBAL"):
            continue
        va = e.get("va")
        status = str(e.get("status", ""))
        if not va or status not in _STATUS_BOOKMARK_CATEGORY:
            continue
        out.append(
            _bookmark_cmd(program_path, f"0x{va:08X}", _STATUS_BOOKMARK_CATEGORY[status], status)
        )
    return out


def resolve_program_path(cfg: ProjectConfig) -> str:
    """Return the Ghidra program path from config or derive from binary name."""
    configured = getattr(cfg, "ghidra_program_path", "")
    if configured:
        return configured
    return f"/{cfg.target_binary.name}"


def validate_program_path(
    client: httpx.Client,
    endpoint: str,
    program_path: str,
    session_id: str,
) -> str:
    """Best-effort validation of derived programPath against current Ghidra project."""
    try:
        result = fetch_mcp_tool_raw(
            client,
            endpoint,
            "get-current-program",
            {},
            request_id=1,
            session_id=session_id,
        )
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        return program_path

    if not isinstance(result, dict):
        return program_path

    ghidra_path = result.get("programPath")
    if not isinstance(ghidra_path, str) or not ghidra_path:
        return program_path

    if ghidra_path != program_path:
        console.print(
            f"[yellow]warning:[/yellow] Ghidra has '{ghidra_path}' open, but rebrew derived '{program_path}'. "
            f'Add ghidra_program_path = "{ghidra_path}" to [targets.X] in '
            "rebrew-project.toml to fix."
        )
    return ghidra_path


def parse_ghidra_va(va_raw: str | int | None) -> int | None:
    """Normalize a VA from hex string, decimal string, or int to int.  Returns None if invalid."""
    if va_raw is None:
        return None
    if isinstance(va_raw, int):
        return va_raw
    if isinstance(va_raw, str) and va_raw.startswith("0x"):
        try:
            return int(va_raw, 16)
        except ValueError:
            return None
    try:
        return int(va_raw)
    except (ValueError, TypeError):
        return None


def build_new_function_commands(
    registry: dict[int, "RegistryEntry"],
    program_path: str,
    iat_thunks: set[int] | None = None,
) -> list[dict[str, Any]]:
    """Generate create-function commands for functions in the list but not detected by Ghidra."""
    commands: list[dict[str, Any]] = []
    thunk_set = iat_thunks or set()

    for va, entry in sorted(registry.items()):
        if va in thunk_set:
            continue
        detected = entry.get("detected_by", [])
        if "list" in detected and "ghidra" not in detected:
            canonical = entry.get("canonical_size", 0)
            if canonical <= 0:
                continue
            va_hex = f"0x{va:08X}"
            commands.append(
                {
                    "tool": "create-function",
                    "args": {
                        "programPath": program_path,
                        "address": va_hex,
                    },
                    "_meta": {
                        "reason": "list only (not in Ghidra)",
                        "list_size": entry.get("size_by_tool", {}).get("list", 0),
                    },
                }
            )

    return commands


def pull_data(
    cfg: ProjectConfig,
    endpoint: str,
    program_path: str,
    dry_run: bool,
) -> None:
    """Pull data labels from Ghidra and generate rebrew_globals.h.

    Fetches all non-function symbols from Ghidra via ReVa MCP (get-symbols),
    then queries data type info for each (get-data), and writes a header file
    with extern declarations.
    """

    def _canonical_section_name(section_name: str) -> str:
        name = section_name.lower()
        if ".data" in name:
            return ".data"
        if ".rdata" in name or "__const" in name:
            return ".rdata"
        if ".bss" in name or "zerofill" in name:
            return ".bss"
        return section_name

    def _find_section(va: int, sections: list[Any]) -> str:
        for section in sections:
            sec_va = int(getattr(section, "va", 0))
            sec_size = int(getattr(section, "size", 0))
            sec_raw_size = int(getattr(section, "raw_size", 0))
            span = max(sec_size, sec_raw_size)
            if span <= 0:
                continue
            if sec_va <= va < sec_va + span:
                return _canonical_section_name(str(getattr(section, "name", "")))
        return ""

    def _normalize_name(raw_name: str, fallback_addr: str) -> str:
        candidate = raw_name or f"g_{fallback_addr.lower().replace('0x', '')}"
        candidate = _NORMALIZE_NAME_RE.sub("_", candidate)
        if not candidate:
            candidate = f"g_{fallback_addr.lower().replace('0x', '')}"
        if candidate[0].isdigit():
            candidate = f"g_{candidate}"
        return candidate

    _GHIDRA_TYPE_MAP: dict[str, str] = {
        "string": "char",
        "terminatedcstring": "char",
        "dword": "unsigned int",
        "byte": "unsigned char",
        "uchar": "unsigned char",
        "ushort": "unsigned short",
        "word": "unsigned short",
        "wchar16": "unsigned short",
        "unicode": "unsigned short",
        "sbyte": "signed char",
        "short": "short",
        "uint": "unsigned int",
        "ulong": "unsigned long",
        "long": "long",
        "longlong": "long long",
        "ulonglong": "unsigned long long",
        "float": "float",
        "double": "double",
        "bool": "int",
    }

    def _normalize_ghidra_type(dtype: str) -> str:
        """Map Ghidra-specific type names to valid C89 types."""
        lower = dtype.strip().lower()
        mapped = _GHIDRA_TYPE_MAP.get(lower)
        if mapped:
            return mapped
        return dtype.strip()

    def _build_extern_decl(data_type: str, symbol_name: str, length: int) -> tuple[str, str]:
        dtype = data_type.strip()
        lower = dtype.lower()

        if lower in {"pointer", "pointer32"}:
            return f"extern void* {symbol_name};", ""

        ptr_match = re.fullmatch(r"(.+?)\s*\*", dtype)
        if ptr_match:
            base = ptr_match.group(1).strip()
            base_lower = base.lower()
            if re.fullmatch(r"undefined(\d+)?", base_lower):
                return f"extern void* {symbol_name};", ""
            return f"extern {_normalize_ghidra_type(base)}* {symbol_name};", ""

        undef_match = re.fullmatch(r"undefined(\d+)?", lower)
        if undef_match:
            arr_len = max(length, int(undef_match.group(1) or "0"))
            if arr_len > 0:
                return f"extern unsigned char {symbol_name}[{arr_len}];", ""
            return f"extern unsigned char {symbol_name}[];", "unknown size"

        arr_match = re.fullmatch(r"(.+?)\[(.+)\]", dtype)
        if arr_match:
            base = _normalize_ghidra_type(arr_match.group(1).strip())
            dim = arr_match.group(2).strip()
            return f"extern {base} {symbol_name}[{dim}];", ""

        if dtype:
            c_type = _normalize_ghidra_type(dtype)
            is_string_type = lower in {"string", "terminatedcstring"}
            if is_string_type and length > 0:
                return f"extern {c_type} {symbol_name}[{length}];", ""
            elif is_string_type:
                return f"extern {c_type} {symbol_name}[];", ""
            return f"extern {c_type} {symbol_name};", ""

        if length > 0:
            return f"extern unsigned char {symbol_name}[{length}];", "unknown type"
        return f"extern unsigned char {symbol_name}[];", "unknown type/size"

    console.print("Pulling data labels from Ghidra...")

    sections: list[Any] = []
    try:
        from rebrew.binary_loader import load_binary

        binary_info = load_binary(cfg.target_binary, getattr(cfg, "binary_format", "auto"))
        sections = list(binary_info.sections.values())
    except (ImportError, OSError, ValueError, AttributeError) as e:
        console.print(f"[yellow]warning:[/yellow] Could not load binary sections: {e}")

    with httpx.Client(timeout=30.0) as client:
        try:
            session_id = init_mcp_session(client, endpoint)
        except httpx.RequestError as e:
            console.print(f"[yellow]warning:[/yellow] Could not connect to MCP endpoint: {e}")
            return

        try:
            count_result = fetch_mcp_tool_raw(
                client,
                endpoint,
                "get-symbols-count",
                {
                    "programPath": program_path,
                    "filterDefaultNames": True,
                },
                1,
                session_id=session_id,
            )
        except httpx.RequestError as e:
            console.print(f"[yellow]warning:[/yellow] Could not fetch symbols count: {e}")
            return

        total_count = 0
        if isinstance(count_result, dict):
            raw_count = count_result.get("count", 0)
            if isinstance(raw_count, int):
                total_count = raw_count

        page_size = 200
        request_id = 2
        all_symbols: list[dict[str, Any]] = []
        start = 0

        while True:
            try:
                page = fetch_mcp_tool_raw(
                    client,
                    endpoint,
                    "get-symbols",
                    {
                        "programPath": program_path,
                        "startIndex": start,
                        "maxCount": page_size,
                        "filterDefaultNames": True,
                    },
                    request_id,
                    session_id=session_id,
                )
            except httpx.RequestError as e:
                console.print(f"[yellow]warning:[/yellow] Could not fetch symbols page: {e}")
                return

            request_id += 1
            if not isinstance(page, list) or not page:
                break

            all_symbols.extend(sym for sym in page if isinstance(sym, dict))

            start += page_size
            if total_count > 0 and start >= total_count:
                break
            if len(page) < page_size:
                break

        data_symbols = [s for s in all_symbols if not s.get("isFunction", False)]
        if not data_symbols:
            console.print("[yellow]No non-function data symbols found in Ghidra.[/yellow]")
            return

        rows: list[dict[str, Any]] = []
        for sym in data_symbols:
            sym_addr = str(sym.get("address", "")).strip()
            if not sym_addr:
                continue

            try:
                data_info = fetch_mcp_tool_raw(
                    client,
                    endpoint,
                    "get-data",
                    {
                        "programPath": program_path,
                        "addressOrSymbol": sym_addr,
                    },
                    request_id,
                    session_id=session_id,
                )
            except httpx.RequestError as e:
                console.print(f"[yellow]warning:[/yellow] get-data failed at {sym_addr}: {e}")
                continue

            request_id += 1
            if not isinstance(data_info, dict):
                continue

            address = str(data_info.get("address") or sym_addr)
            va = parse_ghidra_va(address)
            if va is None:
                continue

            symbol_name = _normalize_name(
                str(data_info.get("symbolName") or sym.get("name") or ""),
                address,
            )

            length_raw = data_info.get("length", 0)
            length = int(length_raw) if isinstance(length_raw, int | float) else 0
            data_type = str(data_info.get("dataType") or "")
            decl, type_note = _build_extern_decl(data_type, symbol_name, length)
            section_name = _find_section(va, sections)

            note_parts = [f"0x{va:08X}", f"{length} bytes"]
            if type_note:
                note_parts.append(type_note)
            rows.append(
                {
                    "va": va,
                    "section": section_name,
                    "decl": decl,
                    "note": ", ".join(note_parts),
                }
            )

    if not rows:
        console.print("[yellow]No data declarations generated from Ghidra symbols.[/yellow]")
        return

    rows.sort(key=lambda x: int(x["va"]))

    seen_va: set[int] = set()
    deduped: list[dict[str, Any]] = []
    for row in rows:
        va = int(row["va"])
        if va in seen_va:
            continue
        seen_va.add(va)
        deduped.append(row)

    dup_count = len(rows) - len(deduped)
    if dup_count:
        console.print(f"  Deduplicated {dup_count} duplicate address(es)")
    rows = deduped

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        sec = str(row.get("section") or "")
        grouped.setdefault(sec, []).append(row)

    out_file = cfg.reversed_dir / "rebrew_globals.h"
    generated = datetime.now(UTC).isoformat(timespec="seconds")

    header_lines = [
        "/* Auto-generated by rebrew sync --pull-data. DO NOT EDIT.",
        " * Source: Ghidra via ReVa MCP",
        f" * Generated: {generated}",
        " */",
        "",
        "#ifndef REBREW_GLOBALS_H",
        "#define REBREW_GLOBALS_H",
        "",
    ]

    section_order = [".data", ".rdata", ".bss"]
    emitted_sections: set[str] = set()
    for section_name in section_order:
        items = grouped.get(section_name, [])
        if not items:
            continue
        header_lines.append(f"/* {section_name} section globals */")
        header_lines.extend(f"{row['decl']} /* {row['note']} */" for row in items)
        header_lines.append("")
        emitted_sections.add(section_name)

    for section_name in sorted(grouped):
        if section_name in emitted_sections:
            continue
        items = grouped[section_name]
        label = section_name or "(unknown)"
        header_lines.append(f"/* {label} section globals */")
        header_lines.extend(f"{row['decl']} /* {row['note']} */" for row in items)
        header_lines.append("")

    header_lines.append("#endif /* REBREW_GLOBALS_H */")
    header_lines.append("")
    header_text = "\n".join(header_lines)

    if dry_run:
        console.print(f"[yellow]Dry run: would write {out_file} with {len(rows)} globals[/yellow]")
        console.print(header_text)
        return

    atomic_write_text(out_file, header_text, encoding="utf-8")
    console.print(f"Pulled {len(rows)} data labels from Ghidra, wrote {out_file.name}")
