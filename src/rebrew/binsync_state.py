"""binsync_state.py — Shared BinSync-state readers for the binsync CLIs.

``binsync_import`` and ``binsync_diff`` both need the same two indexes over a
BinSync state directory: the raw function/global maps and the local
annotation + catalog overlay.  This module is that single source; it imports
no CLI machinery so both tools stay independently importable.
"""

from __future__ import annotations

import logging
import warnings
from pathlib import Path

import tomlkit

from rebrew.catalog import build_function_registry, parse_function_list, scan_reversed_dir
from rebrew.config import FUNCTION_STRUCTURE_JSON, ProjectConfig

log = logging.getLogger(__name__)


def load_binsync_state(
    state_dir: Path,
) -> tuple[dict[int, dict[str, str]], dict[int, dict[str, str]]]:
    """Load BinSync state directory.

    Returns ``(funcs_by_va, globals_by_va)`` where each value is a raw dict
    of fields (``name``, ``prototype``/``header.type``, etc.).
    """
    funcs: dict[int, dict[str, str]] = {}
    funcs_dir = state_dir / "functions"
    if funcs_dir.is_dir():
        for toml_path in funcs_dir.glob("*.toml"):
            try:
                doc = tomlkit.parse(toml_path.read_text(encoding="utf-8"))
            except Exception:
                log.debug("unparseable BinSync function TOML %s", toml_path.name, exc_info=True)
                continue
            info = doc.get("info", {})
            if not isinstance(info, dict):
                continue
            addr = info.get("addr")
            if addr is None:
                # Try filename as hex VA
                try:
                    addr = int(toml_path.stem, 16)
                except ValueError:
                    continue
            try:
                va = int(str(addr), 0)  # "0x1000" or decimal string/int (sync-review F12)
            except (TypeError, ValueError):
                continue
            entry: dict[str, str] = {}
            name = info.get("name")
            if isinstance(name, str) and name:
                entry["name"] = name
            header = doc.get("header", {})
            if isinstance(header, dict):
                htype = header.get("type")
                if isinstance(htype, str) and htype.strip():
                    entry["prototype"] = htype.strip()
            comments = doc.get("comments", {})
            if isinstance(comments, dict):
                for addr_key, text in comments.items():
                    if not isinstance(text, str):
                        continue
                    try:
                        addr = int(str(addr_key), 0)
                    except (TypeError, ValueError):
                        continue
                    if addr == va + 1 and text.startswith("[rebrew:note]"):
                        entry["note"] = text[len("[rebrew:note]") :].strip()
                    elif addr == va + 2 and text.startswith("[rebrew:ghidra]"):
                        entry["ghidra"] = text[len("[rebrew:ghidra]") :].strip()
            funcs[va] = entry

    globals_map: dict[int, dict[str, str]] = {}
    gv_path = state_dir / "global_vars.toml"
    if gv_path.exists():
        try:
            doc = tomlkit.parse(gv_path.read_text(encoding="utf-8"))
            for _key, entry in doc.items():
                if not isinstance(entry, dict):
                    continue
                addr = entry.get("addr")
                if addr is None:
                    try:
                        addr = int(_key, 0)  # key is "16809984" or "0x01008000"
                    except ValueError:
                        continue
                try:
                    va = int(str(addr), 0)  # hex-aware like the key fallback
                except (TypeError, ValueError):
                    continue
                gname = entry.get("name")
                if isinstance(gname, str) and gname:
                    record: dict[str, str] = {"name": gname}
                    gtype = entry.get("type")
                    if isinstance(gtype, str) and gtype.strip():
                        record["type"] = gtype.strip()
                    gsize = entry.get("size")
                    if gsize is not None:
                        record["size"] = str(gsize)
                    gsection = entry.get("section")
                    if isinstance(gsection, str) and gsection.strip():
                        record["section"] = gsection.strip()
                    globals_map[va] = record
        except Exception:
            log.debug("unparseable BinSync global_vars.toml", exc_info=True)

    return funcs, globals_map


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
    for key in ("exported_at", "content_hash", "commit"):
        val = doc.get(key)
        if isinstance(val, str) and val.strip():
            out[key] = val.strip()
    return out


def load_binsync_structs(state_dir: Path) -> dict[str, dict[str, object]]:
    """Load ``structs/*.toml`` from a BinSync state directory.

    Returns ``{struct name: {"definition": str, "fields": {name: {...}}}}``.
    Entries without a usable definition or field list are skipped.
    """
    structs: dict[str, dict[str, object]] = {}
    structs_dir = state_dir / "structs"
    if not structs_dir.is_dir():
        return structs
    for toml_path in sorted(structs_dir.glob("*.toml")):
        try:
            doc = tomlkit.parse(toml_path.read_text(encoding="utf-8"))
        except Exception:
            log.debug("unparseable BinSync struct TOML %s", toml_path.name, exc_info=True)
            continue
        info = doc.get("info", {})
        name = info.get("name") if isinstance(info, dict) else None
        if not isinstance(name, str) or not name.strip():
            name = toml_path.stem
        definition = doc.get("definition", "")
        if not isinstance(definition, str) or not definition.strip():
            maybe = info.get("definition") if isinstance(info, dict) else None
            definition = maybe if isinstance(maybe, str) else ""
        fields = doc.get("fields", {})
        if not isinstance(definition, str):
            definition = ""
        if not isinstance(fields, dict):
            fields = {}
        if not definition.strip() and not fields:
            continue
        structs[name.strip()] = {"definition": definition, "fields": dict(fields)}
    return structs


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
