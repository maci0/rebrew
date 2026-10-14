"""lib-inspect: list what each member of a COFF archive defines, references, and allocates.

Reproducing a link order needs facts LINK only implies.  A member is pulled
in by the first unresolved symbol it defines, and ``/OPT:REF`` later drops its
unreferenced COMDAT code, so a member can be loaded only for its data: its
``.data``/``.bss`` still occupy the image and its undefined symbols still pull
further members (``__imp_*`` references pull import-library members).  This
command answers, per member: section names, sizes, alignment and COMDAT flag;
external definitions with their section; COMMON (communal) data with its size;
weak aliases; and undefined references.  ``--refs`` and ``--defines`` invert
that table for one symbol.

Short import members (the 20-byte ``0000 FFFF`` header of an import library)
carry no sections; LINK synthesizes the thunk and IAT slot from the DLL name
and imported name they hold, which are printed instead.

Usage::

    rebrew library inspect LIBCMT.LIB --member mbctype.obj
    rebrew library inspect LIBCMT.LIB --refs __imp__GetCPInfo@8
    rebrew library inspect KERNEL32 --defines __imp__GetCPInfo@8 --json
"""

from __future__ import annotations

import struct
from pathlib import Path, PureWindowsPath
from typing import Any

import typer

from rebrew.cli import EXIT_ERROR, TargetOption, console, error_exit, json_print, require_config
from rebrew.formats.archives import parse_archive, stock_lib_cache
from rebrew.utils import container_runtime

# IMAGE_FILE_HEADER is 20 bytes; a short import header starts with Sig1=0, Sig2=0xFFFF.
_IMPORT_SIGNATURE = b"\x00\x00\xff\xff"
_IMPORT_HEADER = struct.Struct("<HHHHIIHH")
# IMPORT_OBJECT_HEADER Type field: bits 0-1 import type, bits 2-4 name type.
_IMPORT_TYPES = ("code", "data", "const")
_NAME_ORDINAL, _NAME_NAME, _NAME_NOPREFIX, _NAME_UNDECORATE = range(4)
# Section characteristics (PE/COFF spec).
_SCN_CNT_UNINITIALIZED_DATA = 0x80
_SCN_LNK_COMDAT = 0x1000
_SCN_ALIGN_SHIFT = 20
_SCN_ALIGN_MASK = 0xF

_EPILOG = (
    "[bold]Examples:[/bold]\n\n"
    "  # Sections, definitions, references\n"
    "  rebrew library inspect LIBCMT.LIB --member mbctype.obj\n\n"
    "  # Members referencing a symbol\n"
    "  rebrew library inspect LIBCMT.LIB --refs __imp__GetCPInfo@8\n\n"
    "  # Configured archive by name\n"
    "  rebrew library inspect KERNEL32 --defines __imp__GetCPInfo@8 --json\n\n"
    "[dim]LIBRARY is a path, or a targets.<name>.external_libs key or spec from rebrew-project.toml; a bare spec resolves to the stock archive cached under .scratch/ (extracted from the toolchain image when missing).[/dim]"
)

app = typer.Typer(
    help=(
        "List COFF archive members: sections (size, alignment, COMDAT), defined, "
        "COMMON, and undefined symbols, and short import members."
    ),
    rich_markup_mode="rich",
    epilog=_EPILOG,
)


def _import_name(symbol: str, name_type: int) -> str | None:
    """The name LINK writes to the import table for a short import member."""
    if name_type == _NAME_ORDINAL:
        return None
    if name_type == _NAME_NAME:
        return symbol
    # NOPREFIX drops one leading ?, @ or _; UNDECORATE also cuts at the first @.
    stripped = symbol[1:] if symbol[:1] in ("?", "@", "_") else symbol
    if name_type == _NAME_NOPREFIX:
        return stripped
    return stripped.split("@", 1)[0]


def inspect_import(member: str, body: bytes) -> dict[str, Any]:
    """Describe a short import member: DLL, symbol, imported name or ordinal."""
    if len(body) < _IMPORT_HEADER.size:
        raise ValueError(f"{member}: truncated import header")
    _, _, _, _, _, size, ordinal_hint, flags = _IMPORT_HEADER.unpack_from(body)
    strings = body[_IMPORT_HEADER.size : _IMPORT_HEADER.size + size].split(b"\0")
    if len(strings) < 2:
        raise ValueError(f"{member}: import member lacks symbol and DLL names")
    symbol = strings[0].decode("ascii", errors="replace")
    dll = strings[1].decode("ascii", errors="replace")
    import_type = flags & 0x3
    name_type = (flags >> 2) & 0x7
    kind = _IMPORT_TYPES[import_type] if import_type < len(_IMPORT_TYPES) else str(import_type)
    defines = [f"__imp_{symbol}"] + ([symbol] if kind == "code" else [])
    return {
        "member": member,
        "kind": "import",
        "dll": dll,
        "symbol": symbol,
        "type": kind,
        "import_name": _import_name(symbol, name_type),
        "ordinal": ordinal_hint if name_type == _NAME_ORDINAL else None,
        "hint": ordinal_hint if name_type != _NAME_ORDINAL else None,
        "defines": defines,
    }


def _section_row(index: int, section: Any) -> dict[str, Any]:
    chars = int(section.characteristics)
    align_bits = (chars >> _SCN_ALIGN_SHIFT) & _SCN_ALIGN_MASK
    return {
        "index": index,
        "name": str(section.name),
        "size": int(section.sizeof_raw_data),
        "align": 1 << (align_bits - 1) if align_bits else None,
        "comdat": bool(chars & _SCN_LNK_COMDAT),
        "uninitialized": bool(chars & _SCN_CNT_UNINITIALIZED_DATA),
        "characteristics": f"0x{chars:08x}",
    }


def inspect_coff(member: str, body: bytes) -> dict[str, Any]:
    """Describe a COFF object member: sections and external symbols."""
    import lief

    from rebrew.gen_flirt_pat import load_coff, parse_coff_aliases

    loaded = load_coff(body)
    if loaded is None:
        return {"member": member, "kind": "unparsed"}
    coff, symbols, names = loaded
    sections = [_section_row(i, s) for i, s in enumerate(coff.sections, start=1)]
    defined: list[dict[str, Any]] = []
    common: list[dict[str, Any]] = []
    undefined: list[str] = []
    external = lief.COFF.Symbol.STORAGE_CLASS.EXTERNAL
    for sym, name in zip(symbols, names, strict=True):
        if sym.storage_class != external:
            continue
        index = int(sym.section_idx)
        if index > 0:
            section = sections[index - 1]["name"] if index <= len(sections) else None
            defined.append({"name": name, "section": section, "section_index": index})
        elif index < 0:
            defined.append({"name": name, "section": None, "section_index": index})
        elif sym.value:
            common.append({"name": name, "size": int(sym.value)})
        elif name not in undefined:
            undefined.append(name)
    aliases = [{"name": a, "target": t} for a, t in parse_coff_aliases(body)]
    return {
        "member": member,
        "kind": "coff",
        "sections": sections,
        "defined": defined,
        "common": common,
        "aliases": aliases,
        "undefined": undefined,
    }


def inspect_archive(path: Path) -> list[dict[str, Any]]:
    """One row per archive member, in archive order."""
    rows = []
    for member, body in parse_archive(str(path)):
        if body[:4] == _IMPORT_SIGNATURE:
            rows.append(inspect_import(member, body))
        else:
            rows.append(inspect_coff(member, body))
    return rows


def definitions_of(row: dict[str, Any], symbol: str) -> list[str]:
    """How *row* defines *symbol*: ``section:<name>``, ``common``, ``alias``, ``import``."""
    if row["kind"] == "import":
        return ["import"] if symbol in row["defines"] else []
    if row["kind"] != "coff":
        return []
    found = [f"section:{d['section']}" for d in row["defined"] if d["name"] == symbol]
    found += ["common" for c in row["common"] if c["name"] == symbol]
    found += ["alias" for a in row["aliases"] if a["name"] == symbol]
    return found


def _member_selected(member: str, wanted: set[str]) -> bool:
    return not wanted or bool({member.casefold(), PureWindowsPath(member).name.casefold()} & wanted)


def resolve_archive(library: str, target: str | None, *, json_mode: bool) -> Path:
    """A path as given, else the configured ``external_libs`` archive named *library*.

    A key (``LIBCMT``) or spec (``LIBCMT.lib``) selects the entry.  A spec with
    a directory is a project-relative path; a bare spec is the stock archive
    cached under ``.scratch/``, extracted from the toolchain image when absent.
    """
    from rebrew.compiler.toolchain import ToolchainError
    from rebrew.lib_match import ensure_stock_lib

    given = Path(library)
    if given.is_file():
        return given
    cfg = require_config(target=target, json_mode=json_mode)
    wanted = library.casefold()
    specs = [
        spec.strip()
        for key, spec in (getattr(cfg, "external_libs", None) or {}).items()
        if (spec or "").strip()
        and wanted
        in {key.casefold(), spec.strip().casefold(), PureWindowsPath(spec).stem.casefold()}
    ]
    if not specs:
        error_exit(
            f"{library} is neither a file nor a targets.<name>.external_libs entry",
            json_mode=json_mode,
        )
    spec = specs[0]
    if "/" in spec or "\\" in spec:
        path = Path(spec.replace("\\", "/"))
        path = path if path.is_absolute() else cfg.root / path
        if not path.is_file():
            error_exit(f"configured archive {path} does not exist", json_mode=json_mode)
        return path
    for name in (spec, spec.upper()):
        cached = stock_lib_cache(cfg.root, name, cfg.compiler_profile)
        if cached.is_file():
            return cached
    cached = stock_lib_cache(cfg.root, spec, cfg.compiler_profile)
    try:
        if not ensure_stock_lib(cached, profile=cfg.compiler_profile, name=spec):
            error_exit(
                f"{spec} is not cached and {container_runtime()} is not available to extract it",
                json_mode=json_mode,
            )
    except ToolchainError as exc:
        error_exit(str(exc), json_mode=json_mode, code=EXIT_ERROR)
    return cached


def _say(text: str) -> None:
    """Print archive-derived text literally: no markup, highlighting, or hard wraps."""
    console.print(text, markup=False, highlight=False, soft_wrap=True)


def _print_member(row: dict[str, Any]) -> None:
    if row["kind"] == "import":
        target = row["import_name"] or f"ordinal {row['ordinal']}"
        _say(f"{row['member']}  import {row['symbol']} -> {row['dll']}!{target} ({row['type']})")
        return
    _say(row["member"])
    if row["kind"] != "coff":
        _say("  (not a COFF object LIEF can parse)")
        return
    for s in row["sections"]:
        flags = " ".join(
            f for f, on in (("comdat", s["comdat"]), ("uninit", s["uninitialized"])) if on
        )
        align = s["align"] if s["align"] is not None else "-"
        _say(f"  #{s['index']:<3} {s['name']:<10} size 0x{s['size']:x} align {align} {flags}")
    for label, items in (
        ("defined", [f"{d['name']} ({d['section']}#{d['section_index']})" for d in row["defined"]]),
        ("common", [f"{c['name']} (0x{c['size']:x})" for c in row["common"]]),
        ("aliases", [f"{a['name']} -> {a['target']}" for a in row["aliases"]]),
        ("undefined", row["undefined"]),
    ):
        if items:
            _say(f"  {label}: " + ", ".join(items))


@app.callback(invoke_without_command=True)
def main(
    library: str = typer.Argument(
        ..., help="Archive path, or an external_libs key/spec from rebrew-project.toml"
    ),
    member: list[str] | None = typer.Option(
        None,
        "--member",
        "-m",
        help="Only this member (full archive name or basename, repeatable)",
    ),
    refs: str | None = typer.Option(
        None,
        "--refs",
        help="List the members with an undefined reference to SYMBOL; excludes --defines",
    ),
    defines: str | None = typer.Option(
        None,
        "--defines",
        help="List the members that define SYMBOL (section, COMMON, alias, import); excludes --refs",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """List what each archive member defines, references, and allocates."""
    if refs is not None and defines is not None:
        error_exit("--refs and --defines are separate queries; pass one", json_mode=json_output)
    path = resolve_archive(library, target, json_mode=json_output)
    wanted = {m.casefold() for m in member or []}
    try:
        rows = [r for r in inspect_archive(path) if _member_selected(r["member"], wanted)]
    except (OSError, ValueError, struct.error) as exc:
        error_exit(f"cannot read {path}: {exc}", json_mode=json_output)
    if wanted and not rows:
        error_exit(f"no member of {path} matches {sorted(wanted)}", json_mode=json_output)

    if refs is not None:
        hits = [r["member"] for r in rows if r["kind"] == "coff" and refs in r["undefined"]]
        if json_output:
            json_print({"archive": str(path), "refs": refs, "members": hits, "count": len(hits)})
            return
        for name in hits:
            _say(name)
        _say(f"{len(hits)} member(s) reference {refs}")
        return

    if defines is not None:
        found = [
            {"member": r["member"], "how": how} for r in rows for how in definitions_of(r, defines)
        ]
        if json_output:
            json_print(
                {"archive": str(path), "defines": defines, "members": found, "count": len(found)}
            )
            return
        for hit in found:
            _say(f"{hit['member']}  {hit['how']}")
        _say(f"{len(found)} definition(s) of {defines}")
        return

    if json_output:
        json_print({"archive": str(path), "members": rows, "count": len(rows)})
        return
    for row in rows:
        _print_member(row)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
