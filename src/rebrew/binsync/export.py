"""export.py — Export rebrew annotations to a BinSync state directory.

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
        enums.toml       -- one table per enum (with member values)
        typedefs.toml    -- one table per standalone typedef

The export carries only BinSync-native fields — rebrew's STATUS/CFLAGS
stay in ``rebrew-functions.toml`` (STATUS is verify-earned; an old
``[rebrew] STATUS=… CFLAGS=…`` comment was write-only and was removed).
"""

from __future__ import annotations

import datetime
import logging
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import tomlkit
import typer

from rebrew.annotation import span_contains_factory
from rebrew.binsync import serial
from rebrew.c_parser import type_from_declaration
from rebrew.catalog import scan_reversed_dir
from rebrew.cli import TargetOption, console, error_exit, json_print, require_config, run_standalone
from rebrew.config import ProjectConfig, inventory_path_for
from rebrew.utils import atomic_write_locked, md5_file, strip_body

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
        "[dim]Produces BinSync-compatible TOML layout: functions/, global_vars.toml, "
        "structs/ — BinSync-native fields only (STATUS/CFLAGS stay in "
        "rebrew-functions.toml).[/dim]"
    ),
)


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Global type resolution
# ---------------------------------------------------------------------------


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
            from rebrew.sources import iter_sources as _iter_sources

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
                    if cand_decl.startswith("#"):
                        # Preprocessor directive (#include/#define/#pragma) is
                        # not a declaration.  A DATA marker placed above one
                        # (synthetic link-stub VAs like notepad's 0xDEADBEEF)
                        # must fall through to the g_<hex> fallback instead of
                        # fabricating a name/type from the directive.
                        continue
                    ext_vars = _find_extern(cand_decl)
                    if ext_vars:
                        return ext_vars[0].name, ext_vars[0].type_str
                    # Bare declaration (no extern) — try regex extraction.
                    # The extracted name must be a plain C identifier: a
                    # function-definition line ('void f(void) {}') or other
                    # non-declaration yields '{}'/'{' and must be skipped,
                    # not fabricated into a name/type.
                    decl_name = (
                        cand_decl.split(";")[0].split()[-1].split("[")[0].split("*")[-1].strip()
                    )
                    if (
                        decl_name
                        and decl_name != cand_decl
                        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", decl_name)
                    ):
                        t = type_from_declaration(cand_decl, decl_name)
                        if t:
                            return decl_name, t
                break
    except Exception:
        logger.debug("name/type resolve failed for VA 0x%x", va, exc_info=True)
    return None, None


def _resolve_global_types(
    cfg: ProjectConfig,
    global_entries: Sequence[object],
) -> dict[int, str]:
    """Map VA → C type string for each global entry.

    Uses :func:`rebrew.c_parser.find_extern_variables` on the declaration
    line that follows each ``// GLOBAL:`` / ``// DATA:`` marker, which is
    the authoritative source (also handles non-extern DATA declarations).
    Falls back to :func:`rebrew.data_scan.scan_globals` name→type index when
    the direct parse finds no extern.
    """
    va_to_type: dict[int, str] = {}

    # Build a name→type index from scan_globals as a supplementary source
    name_to_type: dict[str, str] = {}
    try:
        from rebrew.data_scan import scan_globals as _scan_globals

        scan = _scan_globals(cfg.reversed_dir, cfg=cfg)
        for ge in scan.globals.values():
            if ge.type_str and not ge.conflict and ge.name and ge.name != "unknown":
                name_to_type[ge.name] = ge.type_str
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
    global_entries: Sequence[object],
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


def _locals_map(entry: object) -> dict[int, dict[str, object]]:
    """``{offset: {"name", "type", "size"}}`` from an annotation's LOCALS metadata."""
    raw = getattr(entry, "locals", None)
    if not isinstance(raw, dict):
        return {}
    out: dict[int, dict[str, object]] = {}
    for key, value in raw.items():
        if not isinstance(value, dict):
            continue
        try:
            offset = int(str(key), 0)
        except (TypeError, ValueError):
            continue
        out[offset] = value
    return out


def _iter_comment_metadata(entry: object) -> list[tuple[int, int, str]]:
    """``(addr, func_addr, comment)`` triples from an annotation's COMMENTS metadata."""
    raw = getattr(entry, "comments", None)
    if not isinstance(raw, dict):
        return []
    func_addr = int(getattr(entry, "va", 0) or 0)
    out: list[tuple[int, int, str]] = []
    for key, value in raw.items():
        if not isinstance(value, dict):
            continue
        try:
            addr = int(str(key), 0)
        except (TypeError, ValueError):
            continue
        comment = str(value.get("comment") or "")
        if not comment:
            continue
        try:
            owner = int(value.get("func_addr", func_addr))
        except (TypeError, ValueError):
            owner = func_addr
        out.append((addr, owner, comment))
    return out


def _scan_analysis_comments(
    cfg: ProjectConfig, func_entries: list[object]
) -> dict[int, tuple[int, str]]:
    """``{addr: (func_va, comment)}`` from source ``// ANALYSIS @ 0xADDR: text``.

    Scans the target's sources and the project-shared tree; the owning function
    VA is resolved by address containment (falling back to the address itself).
    These markers win over the metadata COMMENTS store for the same address.
    """
    from rebrew.binsync.state import containing_va, parse_analysis_markers
    from rebrew.sources import iter_sources
    from rebrew.utils import read_source_text

    ranges = [
        (int(getattr(e, "va", 0) or 0), int(getattr(e, "size", 0) or 0))
        for e in func_entries
        if getattr(e, "va", 0)
    ]
    paths: list[Path] = []
    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is not None:
        try:
            paths.extend(iter_sources(Path(reversed_dir), cfg))
        except OSError:
            logger.debug("ANALYSIS scan: cannot list %s", reversed_dir, exc_info=True)
    shared_dir = getattr(cfg, "shared_dir", None)
    if shared_dir is not None:
        try:
            paths.extend(iter_sources(Path(shared_dir), cfg))
        except OSError:
            logger.debug("ANALYSIS scan: cannot list %s", shared_dir, exc_info=True)

    out: dict[int, tuple[int, str]] = {}
    for path in paths:
        try:
            # Detected encoding (not UTF-8-replace): a CP1252/Shift-JIS
            # ANALYSIS comment (e.g. "Café") must survive into the export.
            text, _ = read_source_text(path)
        except OSError:
            continue
        for addr, comment in parse_analysis_markers(text).items():
            owner = containing_va(ranges, addr)
            out[addr] = (owner if owner is not None else addr, comment)
    return out


def _as_int(value: object, default: int = 0) -> int:
    """Best-effort int from a metadata value (accepts decimal/hex strings).

    Finite integral floats (``16.0``) are accepted; non-integral floats and
    bools are rejected (``int(True)`` would invent size 1; ``int(12.9)``
    would truncate).  Unparseable values fall back to *default*.
    """
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer() and abs(value) < 1e15:
            return int(value)
        return default
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def _write_function_toml(
    path: Path,
    *,
    name: str,
    va: int,
    size: int,
    prototype: str,
    locals_map: dict[int, dict[str, object]] | None = None,
) -> None:
    """Write one declib ``Function`` artifact.

    Carries the name, addr, size, prototype (body-stripped), and any stack
    variables from the LOCALS metadata.  rebrew's note/ghidra provenance and
    per-instruction comments live in ``comments.toml`` (see
    :func:`_write_comments_toml`), which is where upstream keeps them.
    """
    sig = strip_body(prototype) if prototype else ""
    func = serial.new_function(va, size, name=name or None, prototype=sig or None)
    for offset, variable in (locals_map or {}).items():
        serial.add_stack_variable(
            func,
            offset=offset,
            name=str(variable.get("name") or ""),
            type_=str(variable.get("type") or "") or None,
            size=_as_int(variable.get("size")) or None,
            addr=va,
        )
    serial.dump_artifact(path, func)


def _write_comments_toml(path: Path, comments: list[tuple[int, int, str]]) -> None:
    """Write decib ``Comment`` artifacts keyed by address."""
    artifacts = [
        serial.new_comment(addr, func_addr, comment)
        for addr, func_addr, comment in sorted(comments)
    ]
    serial.dump_many(path, "comment", artifacts, key="addr")


def _write_global_vars_toml(
    path: Path,
    globals_list: list[tuple[int, str, int, str, str | None]],
) -> None:
    """Write declib ``GlobalVariable`` artifacts keyed by address.

    Section is not part of declib's ``GlobalVariable``; import/overlay derive
    it from the binary by address instead of carrying it in the state.
    """
    artifacts = [
        serial.new_global_variable(va, name, type_ or "char", size if size > 0 else None)
        for va, name, size, type_, _section in sorted(globals_list)
    ]
    serial.dump_many(path, "global_variable", artifacts, key="addr")


# ---------------------------------------------------------------------------
# Struct field extraction
# ---------------------------------------------------------------------------


def _parse_struct_fields(typedef_text: str) -> list[dict[str, Any]]:
    """Extract ``{name, type, offset, size}`` field dicts from a typedef-struct string.

    Parses via the shared :mod:`rebrew.types` model (tree-sitter), which
    supplies real member offsets and scalar sizes for the declib Struct.
    Falls back to the legacy brace/body splitter for definitions the shared
    model cannot size, so unrecognized declarator forms still export.
    """
    try:
        from rebrew.types import parse_structs, type_size

        parsed = parse_structs(typedef_text)
        if parsed:
            struct = next(iter(parsed.values()))
            if struct.fields:
                return [
                    {
                        "name": name,
                        "type": spelling,
                        "offset": offset,
                        "size": type_size(spelling) or 0,
                    }
                    for name, spelling, offset in struct.fields
                ]
    except Exception:
        logger.debug("shared struct parse failed, falling back to regex", exc_info=True)

    # Regex fallback: extract body between { and } then split on ;
    m = re.search(r"\{(.*)\}", typedef_text, flags=re.DOTALL)
    if not m:
        return []
    body = m.group(1)
    out: list[dict[str, Any]] = []
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


def _struct_name(typedef_text: str) -> str:
    """Struct name: the typedef alias before ``;``, else the ``struct Name {`` tag."""
    name_match = re.search(r"\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;", typedef_text)
    if name_match:
        return name_match.group(1)
    sm = re.search(r"struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", typedef_text)
    return sm.group(1) if sm else ""


def _collect_struct_definitions(cfg: ProjectConfig) -> dict[str, tuple[str, list[dict[str, Any]]]]:
    """Collect struct definitions from ``reversed_dir`` headers and sources.

    Returns ``{struct_name: (raw_typedef_text, fields)}``.  Prefers the
    header definition when a name appears in both.
    """
    from rebrew.struct_parser import extract_structs_from_file

    result: dict[str, tuple[str, list[dict[str, Any]]]] = {}
    for path in _iter_definition_files(cfg):
        try:
            for typedef_text in extract_structs_from_file(path):
                name = _struct_name(typedef_text)
                if not name or name in result:
                    continue
                result[name] = (typedef_text.strip(), _parse_struct_fields(typedef_text))
        except Exception:
            # One malformed file must not drop every later definition from the export.
            logger.warning("struct collection failed for %s; skipped", path, exc_info=True)
    return result


def _write_struct_toml(
    path: Path,
    name: str,
    fields: list[dict[str, Any]] | None = None,
) -> None:
    """Write one declib ``Struct`` artifact (members keyed by byte offset).

    Missing member offsets/sizes are filled from the field order and
    :func:`rebrew.types.type_size`.
    """
    from rebrew.types import type_size

    members: dict[int, tuple[str, str | None, int | None]] = {}
    next_offset = 0
    for field in fields or []:
        member_name = str(field.get("name") or "")
        if not member_name:
            continue
        member_type = str(field.get("type") or "int")
        size = field.get("size")
        offset = field.get("offset")
        if offset is None:
            offset = next_offset
        member_size = int(size) if size is not None else (type_size(member_type) or 0)
        members[int(offset)] = (member_name, member_type, member_size)
        next_offset = int(offset) + member_size
    size_total = max((off + (m[2] or 0) for off, m in members.items()), default=0)
    serial.dump_artifact(path, serial.new_struct(name, size_total, members))


# ---------------------------------------------------------------------------
# Enum / typedef extraction
# ---------------------------------------------------------------------------


def _iter_definition_files(cfg: ProjectConfig) -> list[Path]:
    """Files scanned for type definitions, in preference order.

    Target-local headers first, then the project-shared header tree, then the
    target's sources; the first definition of a name wins.
    """
    reversed_dir = getattr(cfg, "reversed_dir", None)
    if reversed_dir is None:
        return []
    rd = Path(reversed_dir)
    header_files = sorted(rd.rglob("*.h"))
    shared_dir = getattr(cfg, "shared_dir", None)
    if shared_dir is not None:
        header_files += sorted(Path(shared_dir).rglob("*.h"))
    try:
        from rebrew.sources import iter_sources

        return header_files + list(iter_sources(rd, cfg))
    except OSError:
        logger.warning(
            "cannot list sources under %s; exporting header types only", rd, exc_info=True
        )
        return header_files


def _split_top_level(text: str) -> list[str]:
    """Split *text* on commas at bracket/paren/brace depth zero."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def _enum_name(definition: str) -> str:
    """Enum name: the trailing typedef identifier, else the ``enum Tag`` name."""
    match = re.search(r"\}\s*([A-Za-z_]\w*)\s*;", definition)
    if match:
        return match.group(1)
    match = re.search(r"enum\s+([A-Za-z_]\w*)\s*\{", definition)
    return match.group(1) if match else ""


def _enum_members(definition: str) -> dict[str, int]:
    """``{member: value}`` for an enum body.

    A bare ``IDENT`` (or one whose literal cannot be parsed) takes the
    previous value + 1, starting at 0.
    """
    match = re.search(r"\{(.*)\}", definition, flags=re.DOTALL)
    if not match:
        return {}
    members: dict[str, int] = {}
    next_value = 0
    for entry in _split_top_level(match.group(1)):
        entry = entry.split("//")[0].strip()
        if not entry:
            continue
        if "=" in entry:
            ident, _, literal = entry.partition("=")
            ident = ident.strip()
            try:
                value = int(literal.strip(), 0)
            except ValueError:
                value = next_value
        else:
            ident = entry
            value = next_value
        if not re.fullmatch(r"[A-Za-z_]\w*", ident):
            continue
        members[ident] = value
        next_value = value + 1
    return members


def _collect_enum_definitions(cfg: ProjectConfig) -> dict[str, tuple[str, dict[str, int]]]:
    """Collect ``{enum_name: (raw_definition, {member: value})}``."""
    from rebrew.struct_parser import extract_enums_from_file

    result: dict[str, tuple[str, dict[str, int]]] = {}
    for path in _iter_definition_files(cfg):
        try:
            for text in extract_enums_from_file(path):
                name = _enum_name(text)
                if not name or name in result:
                    continue
                members = _enum_members(text)
                if not members:
                    continue
                result[name] = (text.strip(), members)
        except Exception:
            logger.warning("enum collection failed for %s; skipped", path, exc_info=True)
    return result


def _typedef_name_and_type(definition: str) -> tuple[str, str] | None:
    """``(name, underlying_type)`` for a standalone typedef, else None."""
    text = definition.strip()
    if not text.startswith("typedef"):
        return None
    body = text[len("typedef") :].rstrip().rstrip(";").rstrip()
    identifiers = re.findall(r"[A-Za-z_]\w*", body)
    if not identifiers:
        return None
    name = identifiers[-1]
    idx = body.rfind(name)
    return name, " ".join(body[:idx].split())


def _collect_typedef_definitions(cfg: ProjectConfig) -> dict[str, tuple[str, str]]:
    """Collect ``{name: (raw_definition, underlying_type)}`` for plain typedefs.

    Struct and enum typedefs are excluded (the struct/enum collectors own them).
    """
    from rebrew.struct_parser import extract_type_definitions

    result: dict[str, tuple[str, str]] = {}
    for path in _iter_definition_files(cfg):
        try:
            for text in extract_type_definitions(path):
                if re.search(r"\b(?:struct|enum)\b", text) or "{" in text:
                    continue
                parsed = _typedef_name_and_type(text)
                if parsed is None:
                    continue
                name, underlying = parsed
                if name and name not in result:
                    result[name] = (text.strip(), underlying)
        except Exception:
            logger.warning("typedef collection failed for %s; skipped", path, exc_info=True)
    return result


def _write_enums_toml(path: Path, enums: dict[str, tuple[str, dict[str, int]]]) -> None:
    """Write declib ``enums.toml`` (``Enum.dumps_many`` keyed by name).

    declib's Enum carries only the name and member values; the raw body text
    that :func:`_collect_enum_definitions` collected is not representable and
    is dropped (import synthesizes a typedef from name + members).
    """
    artifacts = [serial.new_enum(name, members) for name, (_raw, members) in sorted(enums.items())]
    serial.dump_many(path, "enum", artifacts, key="name")


def _write_typedefs_toml(path: Path, typedefs: dict[str, tuple[str, str]]) -> None:
    """Write declib ``typedefs.toml`` (``Typedef.dumps_many`` keyed by name)."""
    artifacts = [
        serial.new_typedef(name, underlying)
        for name, (_raw, underlying) in sorted(typedefs.items())
    ]
    serial.dump_many(path, "typedef", artifacts, key="name")


# ---------------------------------------------------------------------------
# Validation + git helpers
# ---------------------------------------------------------------------------


def _validate_binsync_dir(outdir: Path) -> list[str]:
    """Validate a written declib BinSync state directory; return warning strings."""
    warnings: list[str] = []
    funcs_dir = outdir / serial.FUNCTIONS_DIR
    if funcs_dir.is_dir():
        for toml_path in funcs_dir.glob("*.toml"):
            func = serial.load_artifact(toml_path, "function")
            if func is None:
                warnings.append(f"{toml_path.name}: unparseable Function artifact")
                continue
            if func.addr is None:
                warnings.append(f"{toml_path.name}: missing addr")
            if not func.name:
                warnings.append(f"{toml_path.name}: missing name")
    gv = outdir / serial.GLOBAL_VARS_FILE
    if gv.exists():
        for gvar in serial.load_many(gv, "global_variable"):
            if gvar.addr is None or not gvar.name:
                warnings.append("global_vars.toml: entry missing addr/name")
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
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=False, timeout=5)
    except (OSError, subprocess.SubprocessError):
        console.print("[yellow]warning:[/yellow] git not found — skipping commit")
        return None

    try:
        result = subprocess.run(
            ["git", "-C", str(state_dir), "add", "-A"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if result.returncode != 0:
            console.print(f"[yellow]warning:[/yellow] git add failed: {result.stderr.strip()}")
            return None

        status = subprocess.run(
            ["git", "-C", str(state_dir), "status", "--porcelain"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if status.returncode == 0 and not status.stdout.strip():
            console.print("[dim]No changes to commit.[/dim]")
            return None

        utc = datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds")
        msg = f"rebrew binsync-export: {target} @ {utc}"
        commit = subprocess.run(
            ["git", "-C", str(state_dir), "commit", "-m", msg],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
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
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        commit_hash = rev.stdout.strip() if rev.returncode == 0 else None
        if commit_hash:
            console.print(f"[green]Committed[/green] {commit_hash[:8]} — {msg}")
        else:
            console.print(f"[green]Committed[/green] — {msg}")
        return commit_hash
    except (OSError, subprocess.SubprocessError) as exc:
        console.print(f"[yellow]warning:[/yellow] git commit failed: {exc}")
        return None


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

    result = export_state(
        cfg,
        outdir,
        dry_run=dry_run,
        module=module,
        git_commit=git_commit,
        clean=clean,
    )
    print_export_result(result, json_output=json_output, dry_run=dry_run)
    return


def export_state(
    cfg: ProjectConfig,
    outdir: Path,
    *,
    dry_run: bool,
    module: str | None = None,
    git_commit: bool = False,
    clean: bool = False,
) -> dict[str, object]:
    """Export rebrew annotations to a BinSync state directory (programmatic).

    Returns the result dict (counts + written paths + warnings).  ``empty``
    is True when there was nothing to export — the CLI turns that into an
    error, programmatic callers decide.
    """
    entries = scan_reversed_dir(cfg.reversed_dir, cfg=cfg)
    # Optional module filter applies to both annotations and catalog entries
    if module is not None:
        entries = [e for e in entries if getattr(e, "module", "") == module]

    # Partition annotations
    func_entries = [e for e in entries if e.is_function]
    global_entries = [e for e in entries if e.is_data]

    # Also include functions from the project file / catalog that have not yet
    # been reversed (no .c annotation).  This makes BinSync reflect the full
    # binary, not just the reversed subset, so that collaborators see the
    # complete function list with offsets and sizes.
    catalog_func_entries: list[object] = []
    try:
        import warnings

        from rebrew.catalog import build_function_registry, cached_function_list

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            funcs = cached_function_list(cfg)
        ghidra_path = inventory_path_for(cfg.reversed_dir, cfg)
        bin_path = cfg.target_binary
        registry = build_function_registry(funcs, cfg, ghidra_path, bin_path)
        reversed_vas = {e.va for e in func_entries}
        # `va in reversed_vas` is an exact START match, so a catalog VA falling
        # *inside* an annotated function was exported as a separate function.
        # Heuristic discovery produces these constantly: it emits switch arms as
        # pseudo-functions (`case.0x1000ad61.*`) and splits bodies it cannot
        # walk.  Exporting them pollutes the shared state, and because import
        # reads the same state back, `sync --pull` then proposes creating them
        # as real functions -- inside code that is already EXACT/RELOC.
        # Build spans from the annotated sizes and skip anything they contain.
        annotated_spans = sorted(
            (e.va, e.va + int(getattr(e, "size", 0) or 0))
            for e in func_entries
            if int(getattr(e, "size", 0) or 0) > 0
        )
        _inside_annotated = span_contains_factory(annotated_spans)

        for va, reg_entry in registry.items():
            if va in reversed_vas or _inside_annotated(va):
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
    except Exception as exc:
        # A failed catalog scan would silently ship an incomplete export
        # (every not-yet-reversed function missing) — surface it.
        logger.warning("Catalog scan failed — export omits catalog-only functions", exc_info=True)
        console.print(
            f"[yellow]warning:[/] catalog scan failed ({exc.__class__.__name__}: {exc}); "
            "export includes annotations only, no catalog-only functions"
        )

    if module is not None:
        # Catalog-only entries carry no module attribution (""), so under a
        # --module filter they would all be exported unconditionally,
        # violating the filter contract.
        catalog_func_entries = []

    # Nothing at all to export?
    if not func_entries and not catalog_func_entries and not global_entries:
        return {
            "outdir": str(outdir),
            "dry_run": dry_run,
            "functions": 0,
            "globals": 0,
            "structs": 0,
            "enums": 0,
            "typedefs": 0,
            "function_files": [],
            "global_vars_file": None,
            "struct_files": [],
            "enums_file": None,
            "typedefs_file": None,
            "comments": 0,
            "comments_file": None,
            "metadata_file": None,
            "empty": True,
        }

    # Collect global vars with real names + types
    va_to_name = _resolve_global_names(cfg, global_entries)
    va_to_type = _resolve_global_types(cfg, global_entries)
    globals_list: list[tuple[int, str, int, str, str | None]] = []
    for e in global_entries:
        gname = va_to_name.get(e.va) or e.symbol or e.name or f"g_{e.va:08x}"
        gtype = va_to_type.get(e.va, "char")
        section = getattr(e, "section", "") or None
        globals_list.append((e.va, gname, e.size, gtype, section))

    # Collect struct definitions: prefer real definitions from headers/sources,
    # fall back to annotation STRUCT: names for any not found in sources
    struct_defs = _collect_struct_definitions(cfg)
    for e in func_entries:
        if e.struct and e.struct not in struct_defs:
            struct_defs[e.struct] = (f"/* placeholder for {e.struct} */", [])

    enum_defs = _collect_enum_definitions(cfg)
    typedef_defs = _collect_typedef_definitions(cfg)

    if not dry_run:
        funcs_dir = outdir / "functions"
        funcs_dir.mkdir(parents=True, exist_ok=True)
        if struct_defs:
            (outdir / "structs").mkdir(parents=True, exist_ok=True)

    # Merge annotation funcs + catalog-only funcs for export
    all_func_entries: list[object] = list(func_entries) + list(catalog_func_entries)
    written_funcs: list[str] = []
    comment_artifacts: list[tuple[int, int, str]] = []
    metadata_comments: dict[int, tuple[int, str]] = {}
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
                locals_map=_locals_map(entry),
            )
        written_funcs.append(str(func_path))

        # rebrew provenance comments live in comments.toml (upstream's home
        # for them), not the function file.
        note = getattr(entry, "note", "")
        ghidra = getattr(entry, "ghidra", "")
        if note:
            comment_artifacts.append((va + 1, va, f"[rebrew:note] {note}"))
        if ghidra and ghidra != name:
            comment_artifacts.append((va + 2, va, f"[rebrew:ghidra] {ghidra}"))
        for addr, owner, text in _iter_comment_metadata(entry):
            metadata_comments[addr] = (owner, text)

    # A source ``// ANALYSIS @ 0xADDR: text`` marker wins over the metadata
    # entry for the same address (the analyst edited it in source), so edits
    # flow out to comments.toml.
    merged_comments = dict(metadata_comments)
    merged_comments.update(_scan_analysis_comments(cfg, all_func_entries))
    comment_artifacts.extend(
        (addr, owner, text) for addr, (owner, text) in sorted(merged_comments.items())
    )

    written_comments = ""
    if comment_artifacts:
        comments_path = outdir / "comments.toml"
        if not dry_run:
            _write_comments_toml(comments_path, comment_artifacts)
        written_comments = str(comments_path)

    written_globals = ""
    if globals_list:
        global_path = outdir / "global_vars.toml"
        if not dry_run:
            _write_global_vars_toml(global_path, globals_list)
        written_globals = str(global_path)

    written_structs: list[str] = []
    for sname in sorted(struct_defs):
        fields = struct_defs[sname][1]
        spath = outdir / "structs" / f"{serial.sanitize_name(sname)}.toml"
        if not dry_run:
            _write_struct_toml(spath, sname, fields=fields or None)
        written_structs.append(str(spath))

    written_enums = ""
    if enum_defs:
        enum_path = outdir / "enums.toml"
        if not dry_run:
            _write_enums_toml(enum_path, enum_defs)
        written_enums = str(enum_path)

    written_typedefs = ""
    if typedef_defs:
        typedef_path = outdir / "typedefs.toml"
        if not dry_run:
            _write_typedefs_toml(typedef_path, typedef_defs)
        written_typedefs = str(typedef_path)

    # State.parse requires metadata.toml; user is the repo identity or rebrew.
    metadata_file = ""
    if not dry_run:
        serial.write_metadata(outdir, user=serial.state_user(outdir))
        metadata_file = str(outdir / serial.METADATA_FILE)

    # BinSync binds a repo to one binary through the MD5 at its root.  Emit it
    # so a state dir is self-identifying and doctor can catch a dir pointed at
    # the wrong target.
    binary_hash = ""
    if not dry_run:
        binary_hash = _write_binary_hash(outdir, cfg)

    # --clean before manifest/git so the committed tree matches on-disk state
    # and a re-export with identical content is a no-op.
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
        except Exception as exc:
            # --clean is an explicit request: silently skipping it would leave
            # the user believing stale TOMLs are gone (state-dir drift).
            logger.warning("Orphan TOML cleanup failed", exc_info=True)
            console.print(
                f"[yellow]warning:[/] --clean failed ({exc.__class__.__name__}: {exc}); "
                "orphan TOMLs were left in place"
            )

    # Validation warnings (non-fatal)
    warnings_list: list[str] = []
    if not dry_run:
        warnings_list = _validate_binsync_dir(outdir)
        for w in warnings_list:
            console.print(f"[yellow]warning:[/yellow] {w}")

    # Freshness manifest BEFORE git so an unchanged re-export leaves a clean
    # tree (no post-commit timestamp dirt that the next --git would commit).
    # The commit id is returned in the CLI result / git log — writing it back
    # into manifest.toml after commit would re-dirty the working tree.
    manifest_hash = ""
    if not dry_run:
        manifest_hash = _write_manifest(
            outdir,
            None,
            target=getattr(cfg, "target_name", "") or "",
            binary_hash=binary_hash,
        )

    # Optional git commit (opt-in, after all writes including manifest)
    commit_hash: str | None = None
    if git_commit and not dry_run:
        commit_hash = _git_commit_state_dir(outdir, cfg.target_name or cfg.marker or "default")

    return {
        "outdir": str(outdir),
        "dry_run": dry_run,
        "functions": len(written_funcs),
        "globals": len(globals_list),
        "structs": len(written_structs),
        "enums": len(enum_defs),
        "typedefs": len(typedef_defs),
        "function_files": written_funcs,
        "global_vars_file": written_globals or None,
        "struct_files": written_structs,
        "enums_file": written_enums or None,
        "typedefs_file": written_typedefs or None,
        "comments": len(comment_artifacts),
        "comments_file": written_comments or None,
        "metadata_file": metadata_file or None,
        "warnings": warnings_list,
        "cleaned": cleaned,
        "commit": commit_hash,
        "manifest": manifest_hash,
        "binary_hash": binary_hash,
        "module": module,
        "empty": False,
    }


def _write_binary_hash(outdir: Path, cfg: ProjectConfig) -> str:
    """Write ``binary_hash`` (MD5 of the target binary) to the state root.

    Returns the digest, or "" when the target binary is unavailable (the
    check that consumes it skips rather than reporting a false mismatch).
    """
    binary = getattr(cfg, "target_binary", None)
    if binary is None or not Path(binary).exists():
        return ""
    digest = md5_file(Path(binary))
    atomic_write_locked(outdir / "binary_hash", digest, encoding="utf-8")
    return digest


def _write_manifest(
    outdir: Path,
    commit_hash: str | None,
    *,
    target: str = "",
    binary_hash: str = "",
) -> str:
    """Write ``manifest.toml`` (timestamp, content hash, commit) and return the hash.

    Idempotent: when ``content_hash`` / ``target`` / ``binary_hash`` match the
    existing manifest, the file is left untouched (``exported_at`` preserved)
    unless only the ``commit`` field needs updating — then ``exported_at`` is
    still preserved so a re-export cannot create timestamp-only git churn.
    """
    import hashlib
    from datetime import UTC, datetime

    digest = hashlib.sha256()
    for path in sorted(outdir.rglob("*.toml")):
        if path.name == "manifest.toml":
            continue
        try:
            digest.update(path.read_bytes())
        except OSError:
            # Omitting a real artifact silently makes content_hash claim
            # "unchanged" when the unread file still differs on disk.
            logger.warning("manifest hash skipped unreadable %s", path, exc_info=True)
            continue
    content_hash = digest.hexdigest()
    manifest_path = outdir / "manifest.toml"
    existing: dict[str, Any] | None = None
    if manifest_path.exists():
        try:
            # utf-8-sig: Windows editors may prefix EF BB BF; plain utf-8
            # leaves U+FEFF and tomlkit rejects the file (EmptyKeyError).
            parsed = tomlkit.parse(manifest_path.read_text(encoding="utf-8-sig"))
            if isinstance(parsed, dict):
                existing = dict(parsed)
        except (OSError, TypeError, ValueError, tomlkit.exceptions.TOMLKitError):
            existing = None
    if existing is not None and existing.get("content_hash") == content_hash:
        same_target = not target or existing.get("target") == target
        same_binary = not binary_hash or existing.get("binary_hash") == binary_hash
        if same_target and same_binary:
            existing_commit = existing.get("commit")
            if commit_hash is None or commit_hash == existing_commit:
                # Fully unchanged — no rewrite, no timestamp bump.
                return content_hash
            # Content same; only the commit field needs a touch.
            doc = tomlkit.document()
            doc["exported_at"] = existing.get("exported_at") or datetime.now(UTC).isoformat()
            doc["content_hash"] = content_hash
            if target or existing.get("target"):
                doc["target"] = target or existing.get("target")
            if binary_hash or existing.get("binary_hash"):
                doc["binary_hash"] = binary_hash or existing.get("binary_hash")
            doc["commit"] = commit_hash
            atomic_write_locked(manifest_path, tomlkit.dumps(doc), encoding="utf-8")
            return content_hash
    doc = tomlkit.document()
    doc["exported_at"] = datetime.now(UTC).isoformat()
    doc["content_hash"] = content_hash
    if target:
        doc["target"] = target
    if binary_hash:
        doc["binary_hash"] = binary_hash
    if commit_hash:
        doc["commit"] = commit_hash
    atomic_write_locked(manifest_path, tomlkit.dumps(doc), encoding="utf-8")
    return content_hash


def print_export_result(result: dict[str, object], *, json_output: bool, dry_run: bool) -> None:
    """Render an :func:`export_state` result (the CLI summary path)."""
    if bool(result.get("empty")):
        error_exit("No annotations found.", json_mode=json_output)
    from typing import cast

    outdir = str(result["outdir"])
    written_funcs = int(cast(int, result["functions"]))
    globals_list = int(cast(int, result["globals"]))
    written_structs = int(cast(int, result["structs"]))
    written_enums = int(cast(int, result.get("enums") or 0))
    written_typedefs = int(cast(int, result.get("typedefs") or 0))
    written_comments = int(cast(int, result.get("comments") or 0))
    warnings_list = list(cast(list[Any], result.get("warnings") or []))
    cleaned = list(cast(list[Any], result.get("cleaned") or []))
    commit_hash = result.get("commit")
    module = result.get("module")
    if json_output:
        payload: dict[str, object] = {
            "outdir": outdir,
            "dry_run": dry_run,
            "functions": written_funcs,
            "globals": globals_list,
            "structs": written_structs,
            "enums": written_enums,
            "typedefs": written_typedefs,
            "comments": written_comments,
            "function_files": list(cast(list[Any], result.get("function_files") or [])),
            "global_vars_file": result.get("global_vars_file"),
            "struct_files": list(cast(list[Any], result.get("struct_files") or [])),
            "enums_file": result.get("enums_file"),
            "typedefs_file": result.get("typedefs_file"),
            "comments_file": result.get("comments_file"),
            "metadata_file": result.get("metadata_file"),
        }
        if warnings_list:
            payload["warnings"] = warnings_list
        if cleaned:
            payload["cleaned"] = cleaned
        if commit_hash:
            payload["commit"] = commit_hash
        if module is not None:
            payload["module"] = module
        json_print(payload)
    else:
        action = "[dim]would write[/dim]" if dry_run else "Wrote"
        console.print(
            f"{action} [bold]{written_funcs}[/bold] functions, "
            f"[bold]{globals_list}[/bold] globals, "
            f"[bold]{written_structs}[/bold] structs, "
            f"[bold]{written_enums}[/bold] enums, "
            f"[bold]{written_typedefs}[/bold] typedefs, "
            f"[bold]{written_comments}[/bold] comments "
            f"to [cyan]{outdir}[/cyan]"
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    run_standalone(main)


if __name__ == "__main__":
    main_entry()
