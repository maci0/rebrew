"""binsync_export.py — Export rebrew annotations to a BinSync state directory.

Writes function metadata, global variables, and struct definitions in
BinSync's TOML layout so any BinSync-aware decompiler plugin can import the
project's reverse-engineering artifacts.

Layout produced::

    <outdir>/
        functions/
            <hex>.toml   -- one per function annotation
        global_vars.toml -- DATA/GLOBAL annotations
        structs/
            <name>.toml  -- one per struct definition (with fields when available)

Rebrew-specific fields (STATUS, CFLAGS) have no BinSync counterpart, so they
are stored as structured comments at the function VA::

    [rebrew] STATUS=EXACT CFLAGS=/O1 /Gd
"""

from __future__ import annotations

import datetime
import logging
import re
import subprocess
from pathlib import Path

import tomlkit
import typer
from rich.console import Console

from rebrew.catalog.loaders import scan_reversed_dir
from rebrew.cli import TargetOption, error_exit, json_print, require_config
from rebrew.config import ProjectConfig
from rebrew.utils import atomic_write_text

app = typer.Typer(
    help="Export rebrew annotations to a BinSync state directory.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew binsync-export ./binsync_state · · · · · · Export all annotations\n\n"
        "  rebrew binsync-export ./state --dry-run · · · · · Preview without writing\n\n"
        "  rebrew binsync-export ./state --json · · · · · · · Machine-readable output\n\n"
        "  rebrew binsync-export ./state --module SERVER · · Export one module only\n\n"
        "  rebrew binsync-export ./state --git · · · · · · · Export + git commit\n\n"
        "[dim]Produces BinSync-compatible TOML layout: functions/, global_vars.toml. "
        "Rebrew-specific metadata (STATUS, CFLAGS) is preserved in [rebrew] comments.[/dim]"
    ),
)

console = Console(stderr=True)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rebrew_comment(status: str, cflags: str) -> str:
    """Build the ``[rebrew] STATUS=… CFLAGS=…`` metadata comment string."""
    parts = []
    if status:
        parts.append(f"STATUS={status}")
    if cflags:
        parts.append(f"CFLAGS={cflags}")
    return f"[rebrew] {' '.join(parts)}" if parts else ""


def _strip_body(prototype: str) -> str:
    """Return the function signature without the body (everything before ``{``).

    ``annotation.prototype`` includes the full C definition including its body.
    BinSync's ``[header].type`` expects only the declaration/signature line.
    """
    brace = prototype.find("{")
    return prototype[:brace].strip() if brace != -1 else prototype.strip()


# ---------------------------------------------------------------------------
# Global type resolution
# ---------------------------------------------------------------------------

_DECL_RE = re.compile(
    r"^(?:extern\s+)?(?P<type>.+?)\s+\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<arr>\[.*\])?\s*;?\s*$"
)


def _type_from_declaration(decl: str, var_name: str) -> str | None:
    """Extract the C type string for *var_name* from a single declaration line."""
    decl = decl.strip().rstrip(";").strip()
    if not decl or var_name not in decl:
        return None
    # Try the decl regex
    m = _DECL_RE.match(decl + ";")
    if m and m.group("name") == var_name:
        t = m.group("type").strip()
        arr = (m.group("arr") or "").strip()
        if arr:
            t = f"{t}{arr}"
        return t or None
    # Fallback: split on var_name
    idx = decl.find(var_name)
    if idx > 0:
        prefix = decl[:idx].strip()
        # Remove leading extern
        if prefix.startswith("extern "):
            prefix = prefix[7:].strip()
        suffix = decl[idx + len(var_name) :].strip()
        if suffix.startswith("["):
            prefix = f"{prefix}{suffix}"
        if prefix:
            return prefix
    return None


def _extract_global_name_and_type(
    cfg: ProjectConfig,
    va: int,
    filepath: str,
) -> tuple[str | None, str | None]:
    """Return ``(name, type_str)`` for the ``// GLOBAL:`` / ``// DATA:`` marker at *va*.

    Parses the declaration line that follows the marker (the next non-comment
    line).  Uses tree-sitter's ``find_extern_variables`` for accurate parsing
    and falls back to a regex extraction.  ``DATA`` declarations may be bare
    (no ``extern``), e.g. ``char g_buf[64];``, so the plain-declaration helper
    is also tried.  Returns ``(None, None)`` if the marker/decl cannot be found.
    """
    try:
        from rebrew.c_parser import (
            find_extern_variables as _find_extern,
        )
        from rebrew.utils import read_source_text as _rts

        cfg_reversed = getattr(cfg, "reversed_dir", None)
        if cfg_reversed is None:
            return None, None
        full = Path(cfg_reversed) / filepath if filepath else None
        if full is None or not full.exists():
            from rebrew.cli import iter_sources as _iter_sources

            found = None
            for cand in _iter_sources(Path(cfg_reversed), cfg):
                try:
                    txt, _ = _rts(cand)
                except OSError:
                    continue
                if f"0x{va:08x}" in txt.lower() or f"0x{va:x}" in txt.lower():
                    found = cand
                    break
            full = found
        if full is None or not full.exists():
            return None, None
        text, _ = _rts(full)
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            if (f"0x{va:08x}" in line.lower() or f"0x{va:x}" in line.lower()) and (
                "GLOBAL:" in line or "DATA:" in line
            ):
                for j in range(idx + 1, min(idx + 4, len(lines))):
                    cand_decl = lines[j].strip()
                    if not cand_decl or cand_decl.startswith("//"):
                        continue
                    ext_vars = _find_extern(cand_decl)
                    if ext_vars:
                        return ext_vars[0].name, ext_vars[0].type_str
                    # Bare declaration (no extern) — try regex extraction
                    decl_name = (
                        cand_decl.split(";")[0].split()[-1].split("[")[0].split("*")[-1].strip()
                    )
                    if decl_name and decl_name != cand_decl:
                        t = _type_from_declaration(cand_decl, decl_name)
                        if t:
                            return decl_name, t
                break
    except Exception:
        logger.debug("name/type resolve failed for VA 0x%x", va, exc_info=True)
    return None, None


def _resolve_global_types(
    cfg: ProjectConfig,
    global_entries: list[object],
) -> dict[int, str]:
    """Map VA → C type string for each global entry.

    Uses :func:`rebrew.c_parser.find_extern_variables` on the declaration
    line that follows each ``// GLOBAL:`` / ``// DATA:`` marker, which is
    the authoritative source (also handles non-extern DATA declarations).
    Falls back to :func:`rebrew.data.scan_globals` name→type index when
    the direct parse finds no extern.
    """
    va_to_type: dict[int, str] = {}

    # Build a name→type index from scan_globals as a supplementary source
    name_to_type: dict[str, str] = {}
    try:
        from rebrew.data import scan_globals as _scan_globals

        scan = _scan_globals(cfg.reversed_dir, cfg=cfg)
        for ge in scan.globals.values():
            t = getattr(ge, "type_str", "")
            if t and "CONFLICT" not in t and ge.name and ge.name != "unknown":
                name_to_type[ge.name] = t
    except Exception:
        logger.debug("scan_globals unavailable for type resolution", exc_info=True)

    for e in global_entries:
        va = getattr(e, "va", 0)
        if va in va_to_type:
            continue
        filepath = getattr(e, "filepath", "")
        _decl_name, found_type = _extract_global_name_and_type(cfg, va, filepath)
        if found_type:
            va_to_type[va] = found_type
            continue
        # Supplementary: if marker-based parse failed, try name-indexed map
        gname = getattr(e, "symbol", "") or getattr(e, "name", "")
        if gname and gname in name_to_type:
            va_to_type[va] = name_to_type[gname]

    return va_to_type


def _resolve_global_names(
    cfg: ProjectConfig,
    global_entries: list[object],
) -> dict[int, str]:
    """Map VA → variable name for each DATA/GLOBAL entry.

    For ``// GLOBAL:`` / ``// DATA:`` blocks the annotation parser does not
    populate ``ann.name``/``ann.symbol`` (it only does for FUNCTION blocks).
    This helper extracts the real variable name from the declaration line that
    follows the marker, so that ``global_vars.toml`` contains ``g_szBuffer``
    rather than ``g_01008000``.  Falls back to ``g_<hex>`` when the decl
    cannot be resolved.
    """
    va_to_name: dict[int, str] = {}
    for e in global_entries:
        va = getattr(e, "va", 0)
        existing = getattr(e, "symbol", "") or getattr(e, "name", "")
        if existing:
            va_to_name[va] = existing
            continue
        filepath = getattr(e, "filepath", "")
        decl_name, _ = _extract_global_name_and_type(cfg, va, filepath)
        if decl_name:
            va_to_name[va] = decl_name
        else:
            va_to_name[va] = f"g_{va:08x}"
    return va_to_name


def _write_function_toml(
    path: Path,
    *,
    name: str,
    va: int,
    size: int,
    prototype: str,
    status: str,
    cflags: str,
    note: str,
    ghidra: str,
) -> None:
    """Serialise one function's metadata to a BinSync function TOML file."""
    doc = tomlkit.document()

    # [info] — identity
    info = tomlkit.table()
    info["name"] = name
    info["addr"] = va
    if size > 0:
        info["size"] = size
    doc["info"] = info

    # [header] — C-level type/prototype (signature only, no body)
    sig = _strip_body(prototype) if prototype else ""
    if sig:
        header = tomlkit.table()
        header["type"] = sig
        doc["header"] = header

    # [comments] — rebrew metadata + analyst notes
    # BinSync uses integer keys (addresses) mapped to comment strings.
    comments: dict[int, str] = {}

    rebrew_meta = _rebrew_comment(status, cflags)
    if rebrew_meta:
        comments[va] = rebrew_meta

    if note:
        comments[va + 1] = f"[rebrew:note] {note}"

    # Only include the ghidra name if it differs from the exported symbol name
    if ghidra and ghidra != name:
        comments[va + 2] = f"[rebrew:ghidra] {ghidra}"

    if comments:
        tbl = tomlkit.table()
        for addr, text in sorted(comments.items()):
            tbl[str(addr)] = text
        doc["comments"] = tbl

    atomic_write_text(path, tomlkit.dumps(doc), encoding="utf-8")


def _write_global_vars_toml(
    path: Path,
    globals_list: list[tuple[int, str, int] | tuple[int, str, int, str | None]],
) -> None:
    """Write global_vars.toml from (va, name, size[, type]) tuples.

    Accepts both 3-tuples ``(va, name, size)`` (back-compat, type defaults to
    ``"char"``) and 4-tuples ``(va, name, size, type)``.
    """
    doc = tomlkit.document()
    for raw in sorted(globals_list):
        if len(raw) == 3:
            va, name, size = raw
            type_str = "char"
        else:
            va, name, size, type_ = raw
            type_str = type_ or "char"
        entry = tomlkit.table()
        entry["name"] = name
        entry["addr"] = va
        if size > 0:
            entry["size"] = size
        entry["type"] = type_str
        doc[str(va)] = entry
    atomic_write_text(path, tomlkit.dumps(doc), encoding="utf-8")


# ---------------------------------------------------------------------------
# Struct field extraction
# ---------------------------------------------------------------------------


def _parse_struct_fields(typedef_text: str) -> list[dict[str, str]]:
    """Extract ``{name, type}`` field dicts from a typedef-struct string.

    Uses a lightweight brace/body parser when tree-sitter is unavailable;
    prefers tree-sitter AST walking when available.
    """
    # Prefer tree-sitter AST for precise type/field splits
    try:
        from rebrew.c_parser import get_ts_parser as _get_parser

        result = _get_parser()
        if result is not None:
            parser, _ = result
            b = typedef_text.encode("utf-8")
            tree = parser.parse(b)
            fields: list[dict[str, str]] = []

            def _node_text(node: object, src: bytes) -> str:
                return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")  # type: ignore[attr-defined]

            def _walk(node: object) -> None:
                if getattr(node, "type", None) == "field_declaration":
                    # Collect type parts + declarator name
                    type_parts: list[str] = []
                    field_name = ""
                    for child in getattr(node, "children", []):
                        ctype = getattr(child, "type", None)
                        if ctype in (
                            "type_qualifier",
                            "primitive_type",
                            "sized_type_specifier",
                            "type_identifier",
                            "struct_specifier",
                            "enum_specifier",
                            "union_specifier",
                        ):
                            type_parts.append(_node_text(child, b))
                        elif ctype == "field_identifier":
                            field_name = _node_text(child, b)
                        elif ctype == "array_declarator":
                            # field int name[4];
                            for sub in getattr(child, "children", []):
                                if getattr(sub, "type", None) == "field_identifier":
                                    field_name = _node_text(sub, b)
                                    break
                            # include suffix in type
                            type_parts.append(_node_text(child, b).replace(field_name, "").strip())
                            # Actually reconstruct: type + declarator
                            # Simpler: use full field text and split
                            full = _node_text(node, b).strip().rstrip(";").strip()
                            # full is like "int x" or "char name[32]"
                            parts = full.rsplit(None, 1)
                            if len(parts) == 2:
                                fields.append(
                                    {
                                        "name": parts[1].split("[")[0],
                                        "type": parts[0]
                                        + full[len(parts[0]) + 1 + len(parts[1].split("[")[0]) :],
                                    }
                                )
                                # The above is messy; fallback to simple
                                return
                    if field_name:
                        t = " ".join(type_parts).strip() or "int"
                        # Handle array suffix already captured
                        fields.append({"name": field_name, "type": t})
                else:
                    for child in getattr(node, "children", []):
                        _walk(child)

            _walk(tree.root_node)
            if fields:
                return fields
    except Exception:
        logger.debug("tree-sitter struct field parse failed, falling back to regex", exc_info=True)

    # Regex fallback: extract body between { and } then split on ;
    m = re.search(r"\{(.*)\}", typedef_text, flags=re.DOTALL)
    if not m:
        return []
    body = m.group(1)
    out: list[dict[str, str]] = []
    for raw_field in body.split(";"):
        raw_field = raw_field.strip()
        if not raw_field:
            continue
        # Strip // comments
        raw_field = raw_field.split("//")[0].strip()
        if not raw_field:
            continue
        # Expect "<type> <name>[array]"
        # Use rsplit to separate name from type
        parts = raw_field.rsplit(None, 1)
        if len(parts) != 2:
            continue
        type_part, name_part = parts
        # name may include array suffix: name[16]
        name_match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*(\[.*\])?", name_part)
        if not name_match:
            continue
        fname = name_match.group(1)
        arr = name_match.group(2) or ""
        ftype = type_part.strip() + arr
        out.append({"name": fname, "type": ftype})
    return out


def _collect_struct_definitions(cfg: ProjectConfig) -> dict[str, tuple[str, list[dict[str, str]]]]:
    """Collect struct definitions from ``reversed_dir`` headers and sources.

    Returns ``{struct_name: (raw_typedef_text, fields)}``.  Prefers the
    header definition when a name appears in both.
    """
    result: dict[str, tuple[str, list[dict[str, str]]]] = {}
    try:
        from rebrew.cli import iter_sources as _iter_sources
        from rebrew.struct_parser import (
            extract_structs_from_file,
        )

        reversed_dir = getattr(cfg, "reversed_dir", None)
        if reversed_dir is None:
            return result
        rd = Path(reversed_dir)
        # Scan headers first (preferred)
        for hfile in sorted(rd.rglob("*.h")):
            for typedef_text in extract_structs_from_file(hfile):
                # Derive struct name from the typedef: last identifier before ;
                name_match = re.search(r"\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", typedef_text)
                name = name_match.group(1) if name_match else ""
                # Also try "struct Name {"
                if not name:
                    sm = re.search(r"struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", typedef_text)
                    name = sm.group(1) if sm else ""
                if not name:
                    continue
                if name not in result:
                    fields = _parse_struct_fields(typedef_text)
                    result[name] = (typedef_text.strip(), fields)
        # Then sources (if header didn't already provide it)
        for cfile in _iter_sources(rd, cfg):
            for typedef_text in extract_structs_from_file(cfile):
                name_match = re.search(r"\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", typedef_text)
                name = name_match.group(1) if name_match else ""
                if not name:
                    sm = re.search(r"struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", typedef_text)
                    name = sm.group(1) if sm else ""
                if not name or name in result:
                    continue
                fields = _parse_struct_fields(typedef_text)
                result[name] = (typedef_text.strip(), fields)
    except Exception:
        logger.debug("struct collection failed", exc_info=True)
    return result


def _write_struct_toml(
    path: Path,
    name: str,
    fields: list[dict[str, str]] | None = None,
    raw_definition: str | None = None,
) -> None:
    """Write a BinSync struct TOML.

    When *fields* is provided, emits ``[fields.<name>]`` tables with ``type``
    (and ``offset`` when known).  Otherwise writes the minimal placeholder
    ``[info]`` table (back-compat).
    """
    doc = tomlkit.document()
    info = tomlkit.table()
    info["name"] = name
    doc["info"] = info
    if raw_definition:
        doc["definition"] = raw_definition
    if fields:
        fields_tbl = tomlkit.table()
        for f in fields:
            f_tbl = tomlkit.table()
            f_tbl["type"] = f.get("type", "int")
            if "offset" in f:
                f_tbl["offset"] = f["offset"]
            if "size" in f:
                f_tbl["size"] = f["size"]
            fields_tbl[f["name"]] = f_tbl
        doc["fields"] = fields_tbl
    atomic_write_text(path, tomlkit.dumps(doc), encoding="utf-8")


# ---------------------------------------------------------------------------
# Validation + git helpers
# ---------------------------------------------------------------------------


def _validate_binsync_dir(outdir: Path) -> list[str]:
    """Validate a written BinSync state directory; return warning strings."""
    warnings: list[str] = []
    funcs_dir = outdir / "functions"
    if funcs_dir.is_dir():
        for toml_path in funcs_dir.glob("*.toml"):
            try:
                doc = tomlkit.parse(toml_path.read_text(encoding="utf-8"))
            except Exception as exc:
                warnings.append(f"{toml_path.name}: unparseable TOML: {exc}")
                continue
            info = doc.get("info", {})
            if not isinstance(info, dict) or not info.get("name"):
                warnings.append(f"{toml_path.name}: missing [info].name")
            if not isinstance(info, dict) or "addr" not in info:
                warnings.append(f"{toml_path.name}: missing [info].addr")
    gv = outdir / "global_vars.toml"
    if gv.exists():
        try:
            doc = tomlkit.parse(gv.read_text(encoding="utf-8"))
            for key, entry in doc.items():
                if not isinstance(entry, dict) or "name" not in entry or "addr" not in entry:
                    warnings.append(f"global_vars.toml[{key}]: missing name/addr")
        except Exception as exc:
            warnings.append(f"global_vars.toml: unparseable: {exc}")
    return warnings


def _git_commit_state_dir(state_dir: Path, target: str) -> str | None:
    """Stage + commit the BinSync state directory.

    Returns the new commit hash on success, ``None`` on skip/failure (caller
    decides whether to surface a warning).
    """
    git_dir = state_dir / ".git"
    if not git_dir.exists():
        console.print(
            f"[yellow]warning:[/yellow] {state_dir} is not a git repository — skipping git commit"
        )
        return None
    # Check git is available
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.SubprocessError):
        console.print("[yellow]warning:[/yellow] git not found — skipping commit")
        return None

    # Stage
    result = subprocess.run(
        ["git", "-C", str(state_dir), "add", "-A"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        console.print(f"[yellow]warning:[/yellow] git add failed: {result.stderr.strip()}")
        return None

    # Check if there's anything to commit
    status = subprocess.run(
        ["git", "-C", str(state_dir), "status", "--porcelain"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if status.returncode == 0 and not status.stdout.strip():
        console.print("[dim]No changes to commit.[/dim]")
        return None

    utc = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    msg = f"rebrew binsync-export: {target} @ {utc}"
    commit = subprocess.run(
        ["git", "-C", str(state_dir), "commit", "-m", msg],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if commit.returncode != 0:
        # Empty commit (nothing changed) is not an error
        if (
            "nothing to commit" in commit.stdout.lower()
            or "nothing to commit" in commit.stderr.lower()
        ):
            console.print("[dim]No changes to commit.[/dim]")
            return None
        console.print(f"[yellow]warning:[/yellow] git commit failed: {commit.stderr.strip()}")
        return None

    # Try to get the new hash
    rev = subprocess.run(
        ["git", "-C", str(state_dir), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    commit_hash = rev.stdout.strip() if rev.returncode == 0 else None
    if commit_hash:
        console.print(f"[green]Committed[/green] {commit_hash[:8]} — {msg}")
    else:
        console.print(f"[green]Committed[/green] — {msg}")
    return commit_hash


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@app.callback(invoke_without_command=True)
def main(
    outdir: Path = typer.Argument(..., help="Output directory for the BinSync state"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    module: str | None = typer.Option(
        None, "--module", help="Only export this module (e.g. SERVER)"
    ),
    git_commit: bool = typer.Option(
        False, "--git", help="Stage and commit the state directory with git"
    ),
    clean: bool = typer.Option(
        False, "--clean", help="Remove orphan function TOMLs no longer in the catalog/annotations"
    ),
    target: str | None = TargetOption,
) -> None:
    """Export rebrew annotations to a BinSync state directory.

    Produces a ``functions/`` tree, ``global_vars.toml``, and ``structs/``
    placeholders compatible with BinSync's TOML state format.
    """
    cfg = require_config(target=target, json_mode=json_output)

    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    # Optional module filter applies to both annotations and catalog entries
    if module is not None:
        entries = [e for e in entries if getattr(e, "module", "") == module]

    # Partition annotations
    func_entries = [e for e in entries if e.marker_type not in ("GLOBAL", "DATA")]
    global_entries = [e for e in entries if e.marker_type in ("GLOBAL", "DATA")]

    # Also include functions from the project file / catalog that have not yet
    # been reversed (no .c annotation).  This makes BinSync reflect the full
    # binary, not just the reversed subset, so that collaborators see the
    # complete function list with offsets and sizes.
    catalog_func_entries: list[object] = []
    try:
        import warnings

        from rebrew.catalog.loaders import parse_function_list
        from rebrew.catalog.registry import build_function_registry
        from rebrew.config import FUNCTION_STRUCTURE_JSON

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            funcs = parse_function_list(cfg.function_list)
        ghidra_path = cfg.reversed_dir / FUNCTION_STRUCTURE_JSON
        bin_path = cfg.target_binary
        registry = build_function_registry(funcs, cfg, ghidra_path, bin_path)
        reversed_vas = {e.va for e in func_entries}
        for va, reg_entry in registry.items():
            if va in reversed_vas:
                continue
            # Skip IAT thunks — they are not user functions
            if reg_entry.get("is_thunk"):
                continue
            size = int(reg_entry.get("canonical_size", 0) or 0)
            if size <= 0:
                continue
            # Fabricate a minimal annotation-like object for export.
            # Keep raw name only (no leading underscore) — the export step
            # derives the symbol, so stdcall decoration @N would be double-counted
            # if we pre-decorate here, and calling convention is unknown for
            # catalog-only entries anyway.
            raw_name = (
                reg_entry.get("list_name") or reg_entry.get("ghidra_name") or f"func_{va:08x}"
            )
            catalog_func_entries.append(
                type(
                    "CatalogFunc",
                    (),
                    {
                        "va": va,
                        "size": size,
                        "name": raw_name,
                        "symbol": "",
                        "module": "",
                        "status": "",
                        "cflags": "",
                        "note": "",
                        "ghidra": "",
                        "prototype": "",
                        "struct": "",
                        "marker_type": "FUNCTION",
                        "filepath": "",
                    },
                )()
            )
    except Exception:
        pass

    # Nothing at all to export?
    if not func_entries and not catalog_func_entries and not global_entries:
        error_exit("No annotations found.", json_mode=json_output)

    # Collect global vars with real names + types
    va_to_name = _resolve_global_names(cfg, global_entries)  # type: ignore[arg-type]
    va_to_type = _resolve_global_types(cfg, global_entries)  # type: ignore[arg-type]
    globals_list: list[tuple[int, str, int, str]] = []
    for e in global_entries:
        gname = va_to_name.get(e.va) or e.symbol or e.name or f"g_{e.va:08x}"
        gtype = va_to_type.get(e.va, "char")
        globals_list.append((e.va, gname, e.size, gtype))

    # Collect struct definitions: prefer real definitions from headers/sources,
    # fall back to annotation STRUCT: names for any not found in sources
    struct_defs = _collect_struct_definitions(cfg)
    # Add any STRUCT: names that weren't found via file scanning (keeps old behavior)
    for e in func_entries:
        if e.struct and e.struct not in struct_defs:
            struct_defs[e.struct] = (f"/* placeholder for {e.struct} */", [])

    if not dry_run:
        funcs_dir = outdir / "functions"
        funcs_dir.mkdir(parents=True, exist_ok=True)
        if struct_defs:
            (outdir / "structs").mkdir(parents=True, exist_ok=True)

    # Merge annotation funcs + catalog-only funcs for export
    all_func_entries: list[object] = list(func_entries) + list(catalog_func_entries)
    written_funcs: list[str] = []
    for entry in all_func_entries:
        va = entry.va  # type: ignore[attr-defined]
        name = getattr(entry, "symbol", "") or getattr(entry, "name", "") or f"func_{va:08x}"

        func_path = outdir / "functions" / f"{va:08x}.toml"
        if not dry_run:
            _write_function_toml(
                func_path,
                name=name,
                va=va,
                size=getattr(entry, "size", 0),
                prototype=getattr(entry, "prototype", ""),
                status=getattr(entry, "status", ""),
                cflags=getattr(entry, "cflags", ""),
                note=getattr(entry, "note", ""),
                ghidra=getattr(entry, "ghidra", ""),
            )
        written_funcs.append(str(func_path))

    written_globals = ""
    if globals_list:
        global_path = outdir / "global_vars.toml"
        if not dry_run:
            _write_global_vars_toml(global_path, globals_list)  # type: ignore[arg-type]
        written_globals = str(global_path)

    written_structs: list[str] = []
    for sname in sorted(struct_defs):
        raw_def, fields = struct_defs[sname]
        # Sanitize struct name: whitelist alphanumeric + _ - to prevent path traversal
        safe_name = "".join(c if c.isalnum() or c in "_-" else "_" for c in sname) or "unnamed"
        spath = outdir / "structs" / f"{safe_name}.toml"
        if not dry_run:
            _write_struct_toml(
                spath, sname, fields=fields or None, raw_definition=raw_def if fields else None
            )
        written_structs.append(str(spath))

    # Optional git commit (opt-in, after all writes)
    commit_hash: str | None = None
    if git_commit and not dry_run:
        commit_hash = _git_commit_state_dir(outdir, cfg.target_name or cfg.marker or "default")

    # --clean: remove orphan TOMLs no longer in catalog/annotations (prevents drift)
    cleaned: list[str] = []
    if clean and not dry_run:
        try:
            alive_vas = {int(e.va) for e in all_func_entries}  # type: ignore[attr-defined]
            funcs_dir = outdir / "functions"
            if funcs_dir.is_dir():
                for p in funcs_dir.glob("*.toml"):
                    try:
                        va = int(p.stem, 16)
                    except ValueError:
                        continue
                    if va not in alive_vas:
                        p.unlink()
                        cleaned.append(str(p))
                if cleaned:
                    console.print(f"[dim]Cleaned {len(cleaned)} orphan TOML(s)[/dim]")
        except Exception:
            pass

    # Validation warnings (non-fatal)
    warnings_list: list[str] = []
    if not dry_run:
        warnings_list = _validate_binsync_dir(outdir)
        for w in warnings_list:
            console.print(f"[yellow]warning:[/yellow] {w}")

    # --- Output ---
    if json_output:
        result: dict[str, object] = {
            "outdir": str(outdir),
            "dry_run": dry_run,
            "functions": len(written_funcs),
            "globals": len(globals_list),
            "structs": len(written_structs),
            "function_files": written_funcs,
            "global_vars_file": written_globals or None,
            "struct_files": written_structs,
        }
        if warnings_list:
            result["warnings"] = warnings_list
        if cleaned:
            result["cleaned"] = cleaned
        if commit_hash:
            result["commit"] = commit_hash
        if module is not None:
            result["module"] = module
        json_print(result)
    else:
        action = "[dim]would write[/dim]" if dry_run else "Wrote"
        console.print(
            f"{action} [bold]{len(written_funcs)}[/bold] functions, "
            f"[bold]{len(globals_list)}[/bold] globals, "
            f"[bold]{len(written_structs)}[/bold] structs "
            f"to [cyan]{outdir}[/cyan]"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
