"""binsync_state.py — Shared BinSync-state readers for the binsync CLIs.

``binsync_import`` and ``binsync_diff`` both need the same indexes over a
BinSync state directory: the raw function/global maps and the local
annotation + catalog overlay.  This module is that single source; it imports
no CLI machinery so both tools stay independently importable.

State is read through :mod:`rebrew.binsync_serial` (declib), so a directory
written by rebrew, BinSync, IDA, Ghidra, or Binary Ninja parses the same way.
"""

from __future__ import annotations

import logging
import re
import warnings
from pathlib import Path
from typing import Any

import tomlkit

from rebrew.catalog import build_function_registry, parse_function_list, scan_reversed_dir
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig

log = logging.getLogger(__name__)

_NOTE_PREFIX = "[rebrew:note]"
_GHIDRA_PREFIX = "[rebrew:ghidra]"

#: Per-address source comment marker (line comment only).  This is the single
#: prefix import writes and export scans; format::
#:
#:     // ANALYSIS @ 0x401010: some note
ANALYSIS_MARKER_PREFIX = "// ANALYSIS @ "

_ANALYSIS_MARKER_RE = re.compile(r"^//\s*ANALYSIS\s*@\s*(0x[0-9a-fA-F]+)\s*:\s?(.*)$")


def parse_analysis_markers(text: str) -> dict[int, str]:
    """Return ``{addr: comment}`` for every per-address ANALYSIS marker line."""
    out: dict[int, str] = {}
    for line in text.splitlines():
        match = _ANALYSIS_MARKER_RE.match(line.strip())
        if match:
            out[int(match.group(1), 16)] = match.group(2).rstrip()
    return out


def containing_va(candidates: list[tuple[int, int]], addr: int) -> int | None:
    """VA of the first ``(va, size)`` candidate whose range contains *addr*."""
    for va, size in candidates:
        if size and va <= addr < va + size:
            return va
    return None


def write_analysis_markers(path: Path, comments: dict[int, str]) -> bool:
    """Merge per-address *comments* into *path*'s trailing ANALYSIS block.

    Existing lines for the same address are updated in place and new addresses
    are appended, so a re-import is idempotent.  The block is sorted by address
    and separated from the code by one blank line.  Returns True when the file
    changed (a no-op rewrite returns False without touching the file).
    """
    from rebrew.utils import atomic_write_text, read_source_text

    if not comments:
        return False
    try:
        text, encoding = read_source_text(path)
    except OSError:
        log.debug("cannot read %s for ANALYSIS markers", path, exc_info=True)
        return False

    merged = parse_analysis_markers(text)
    merged.update(comments)

    kept = [line for line in text.splitlines() if not _ANALYSIS_MARKER_RE.match(line.strip())]
    while kept and not kept[-1].strip():
        kept.pop()
    block = "\n".join(
        f"{ANALYSIS_MARKER_PREFIX}0x{addr:08x}: {merged[addr]}" for addr in sorted(merged)
    )
    body = "\n".join(kept)
    new_text = f"{body}\n\n{block}\n" if body else f"{block}\n"
    if new_text == text:
        return False
    atomic_write_text(path, new_text, encoding=encoding)
    return True


def load_binsync_state(
    state_dir: Path,
) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, Any]]]:
    """Load a declib-backed BinSync state directory.

    Returns ``(funcs_by_va, globals_by_va)``.  Function entries carry
    ``name``/``prototype``/``size``/``stack_vars``; rebrew's note/ghidra
    provenance comments (kept at ``va+1``/``va+2`` in ``comments.toml``) are
    folded back in as ``note``/``ghidra``.  Foreign declib state dirs load the
    same way.
    """
    from rebrew import binsync_serial

    funcs: dict[int, dict[str, Any]] = {}
    funcs_dir = state_dir / binsync_serial.FUNCTIONS_DIR
    if funcs_dir.is_dir():
        for toml_path in sorted(funcs_dir.glob("*.toml")):
            func = binsync_serial.load_artifact(toml_path, "function")
            if func is None:
                continue
            addr = func.addr
            if addr is None:
                try:
                    addr = int(toml_path.stem, 16)
                except ValueError:
                    continue
            entry: dict[str, Any] = {}
            if func.name:
                entry["name"] = func.name
            prototype = func.type
            if isinstance(prototype, str) and prototype.strip():
                entry["prototype"] = prototype.strip()
            if func.size:
                entry["size"] = str(func.size)
            stack_vars: dict[str, dict[str, Any]] = {}
            for offset, var in (func.stack_vars or {}).items():
                stack_vars[str(offset)] = {
                    "name": var.name or "",
                    "type": var.type or "",
                    "size": int(var.size or 0),
                }
            if stack_vars:
                entry["stack_vars"] = stack_vars
            funcs[int(addr)] = entry

    globals_map: dict[int, dict[str, Any]] = {}
    for gvar in binsync_serial.load_many(
        state_dir / binsync_serial.GLOBAL_VARS_FILE, "global_variable"
    ):
        addr = gvar.addr
        if addr is None:
            continue
        record: dict[str, Any] = {}
        if gvar.name:
            record["name"] = gvar.name
        if isinstance(gvar.type, str) and gvar.type.strip():
            record["type"] = gvar.type.strip()
        if gvar.size is not None:
            record["size"] = str(gvar.size)
        globals_map[int(addr)] = record

    # rebrew provenance travels as prefixed comments at va+1 (note) / va+2
    # (ghidra), tagged with the owning function's addr.
    for comment in binsync_serial.load_many(state_dir / binsync_serial.COMMENTS_FILE, "comment"):
        text = comment.comment or ""
        func_addr = comment.func_addr
        if func_addr is None:
            func_addr = (comment.addr or 0) - 1
        func_entry = funcs.get(int(func_addr))
        if func_entry is None:
            continue
        if text.startswith(_NOTE_PREFIX):
            func_entry["note"] = text[len(_NOTE_PREFIX) :].strip()
        elif text.startswith(_GHIDRA_PREFIX):
            func_entry["ghidra"] = text[len(_GHIDRA_PREFIX) :].strip()

    return funcs, globals_map


def load_binsync_comments(state_dir: Path) -> dict[int, dict[str, Any]]:
    """Load ``comments.toml`` as ``{addr: {"comment", "func_addr"}}``."""
    from rebrew import binsync_serial

    out: dict[int, dict[str, Any]] = {}
    for comment in binsync_serial.load_many(state_dir / binsync_serial.COMMENTS_FILE, "comment"):
        if comment.addr is None:
            continue
        out[int(comment.addr)] = {
            "comment": comment.comment or "",
            "func_addr": int(comment.func_addr) if comment.func_addr is not None else None,
        }
    return out


def load_manifest(state_dir: Path) -> dict[str, str]:
    """Read ``manifest.toml`` freshness facts; empty dict when absent."""
    manifest = state_dir / "manifest.toml"
    if not manifest.exists():
        return {}
    try:
        doc = tomlkit.parse(manifest.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: dict[str, str] = {}
    for key in ("exported_at", "content_hash", "commit", "target", "binary_hash"):
        val = doc.get(key)
        if isinstance(val, str) and val.strip():
            out[key] = val.strip()
    return out


def load_binsync_structs(state_dir: Path) -> dict[str, dict[str, object]]:
    """Load ``structs/*.toml`` declib Structs.

    Returns ``{name: {"definition": synthesized_typedef, "fields": {name:
    {"type", "offset", "size"}}}}``.  The synthesized definition lets the
    import path reuse the same shared type-model validation as before.
    """
    from rebrew import binsync_serial

    structs: dict[str, dict[str, object]] = {}
    structs_dir = state_dir / binsync_serial.STRUCTS_DIR
    if not structs_dir.is_dir():
        return structs
    for toml_path in sorted(structs_dir.glob("*.toml")):
        struct = binsync_serial.load_artifact(toml_path, "struct")
        if struct is None:
            continue
        name = struct.name
        if not isinstance(name, str) or not name.strip():
            name = toml_path.stem
        members: dict[int, Any] = dict(struct.members or {})
        fields: dict[str, dict[str, object]] = {}
        lines: list[str] = []
        for offset in sorted(members):
            member = members[offset]
            member_type = member.type or "int"
            fields[member.name] = {
                "type": member_type,
                "offset": offset,
                "size": int(member.size or 0),
            }
            lines.append(f"\t{member_type} {member.name};")
        definition = f"typedef struct {name} {{\n" + "\n".join(lines) + f"\n}} {name};"
        structs[name.strip()] = {"definition": definition, "fields": fields}
    return structs


def load_binsync_enums(state_dir: Path) -> dict[str, dict[str, object]]:
    """Load ``enums.toml`` declib Enums.

    Returns ``{name: {"definition": synthesized_typedef, "members":
    {MEMBER: int}}}``.  declib carries no enum body text, so the definition is
    synthesized from the members for the import path."""
    from rebrew import binsync_serial

    enums: dict[str, dict[str, object]] = {}
    for enum in binsync_serial.load_many(state_dir / binsync_serial.ENUMS_FILE, "enum"):
        name = enum.name
        if not isinstance(name, str) or not name.strip():
            continue
        members = {str(k): int(v) for k, v in (enum.members or {}).items()}
        if not members:
            continue
        body = ", ".join(f"{member} = {value}" for member, value in members.items())
        definition = f"typedef enum {{ {body} }} {name};"
        enums[name.strip()] = {"definition": definition, "members": members}
    return enums


def load_binsync_typedefs(state_dir: Path) -> dict[str, dict[str, object]]:
    """Load ``typedefs.toml`` declib Typedefs.

    Returns ``{name: {"definition": synthesized_typedef, "type": underlying}}``.
    """
    from rebrew import binsync_serial

    typedefs: dict[str, dict[str, object]] = {}
    for typedef in binsync_serial.load_many(state_dir / binsync_serial.TYPEDEFS_FILE, "typedef"):
        name = typedef.name
        if not isinstance(name, str) or not name.strip():
            continue
        underlying = typedef.type if isinstance(typedef.type, str) else ""
        definition = " ".join(f"typedef {underlying} {name};".split())
        typedefs[name.strip()] = {"definition": definition, "type": underlying}
    return typedefs


def index_local_and_catalog(
    cfg: ProjectConfig,
) -> tuple[dict[int, object], dict[int, object], set[int]]:
    """Index local annotations by VA and overlay catalog-only VAs.

    The catalog (functions.txt / function_structure.json) is the project file:
    its VAs represent the ground truth binary layout even when no .c file
    exists yet.  Catalog-only VAs land in the second map so callers can
    surface them (stub-able / new-in-BinSync) without overwriting real
    annotations.
    """
    local_entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    local_by_va: dict[int, object] = {}
    for e in local_entries:
        va = getattr(e, "va", 0)
        if va and (va not in local_by_va or getattr(e, "marker_type", "") == "FUNCTION"):
            # Keep FUNCTION entries preferentially; DATA/GLOBAL overwrite only if no function
            local_by_va[va] = e

    catalog_by_va: dict[int, object] = {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            funcs = parse_function_list(cfg.function_list)
        ghidra_path = cfg.reversed_dir / FUNCTION_STRUCTURE_JSON
        registry = build_function_registry(funcs, cfg, ghidra_path, cfg.target_binary)
        for va, reg_entry in registry.items():
            if va in local_by_va:
                continue
            if reg_entry.get("is_thunk"):
                continue
            size = int(reg_entry.get("canonical_size", 0) or 0)
            if size <= 0:
                continue
            raw_name = (
                reg_entry.get("list_name") or reg_entry.get("ghidra_name") or f"func_{va:08x}"
            )
            catalog_by_va[va] = type(
                "CatalogFunc",
                (),
                {
                    "va": va,
                    "size": size,
                    "name": raw_name,
                    "symbol": "",
                    "module": "",
                    "prototype": "",
                    "marker_type": "FUNCTION",
                    "filepath": "",
                    "status": "",
                },
            )()
    except Exception:
        log.debug("catalog scan failed — treating as empty", exc_info=True)

    return local_by_va, catalog_by_va, set(catalog_by_va.keys())
