"""Library data ownership from MSVC link maps and selected COFF archive members.

Map symbol names identify the linked build's storage even when its addresses
have drifted from the reference. An archive definition alone is only a candidate;
COMMON storage needs a member independently selected by the link map.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rebrew.config import ProjectConfig
    from rebrew.data_scan import ScanResult

log = logging.getLogger(__name__)
_MAP_ROW = re.compile(
    r"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8,16}\s+(\S+)\s+([0-9a-fA-F]{8,16})\s+(.+?)\s*$"
)


@dataclass(frozen=True)
class LinkSymbol:
    """One public or static data/code symbol in an MSVC map."""

    name: str
    va: int
    library: str = ""
    member: str = ""
    common: bool = False
    is_function: bool = False
    object: str = ""


def parse_link_map(text: str) -> list[LinkSymbol]:
    """Read MSVC Publics/Static symbols, excluding import-address-table entries."""
    symbols: list[LinkSymbol] = []
    for line in text.splitlines():
        match = _MAP_ROW.match(line)
        if match is None:
            continue
        name, address, origin = match.groups()
        words = origin.split()
        flags: set[str] = set()
        while words and words[0] in {"f", "i"}:
            flags.add(words.pop(0))
        if "i" in flags:
            continue
        origin = " ".join(words)
        library = member = ""
        if ":" in origin:
            archive, obj = origin.rsplit(":", 1)
            # A drive-qualified project object (C:\\src\\game.obj) is not a lib.
            if not (len(archive) == 1 and archive.isalpha()):
                library = PureWindowsPath(archive.strip('"')).name
                member = PureWindowsPath(obj.strip('"')).name
        # DLL import slots are emitted by the linker, not a static archive member.
        if member.casefold().endswith(".dll"):
            continue
        symbols.append(
            LinkSymbol(
                name,
                int(address, 16),
                library,
                member,
                origin == "<common>",
                "f" in flags,
                origin if not library and origin != "<common>" else "",
            )
        )
    return symbols


def _library_key(name: str) -> str:
    return PureWindowsPath(name).stem.casefold()


def _cached_archives(cfg: ProjectConfig) -> dict[str, Path]:
    """Configured archives already on disk; never extract or pull during a scan."""
    from rebrew.archives import stock_lib_cache

    archives: dict[str, Path] = {}
    ambiguous: set[str] = set()
    for spec in (getattr(cfg, "external_libs", None) or {}).values():
        if not spec:
            continue
        if "/" in spec or "\\" in spec:
            path = Path(spec.replace("\\", "/"))
            if not path.is_absolute():
                path = cfg.root / path
        else:
            path = stock_lib_cache(cfg.root, spec, cfg.compiler_profile)
            if not path.is_file():
                # Stock-lib CLI calls commonly use .LIB while config uses .lib.
                path = stock_lib_cache(cfg.root, spec.upper(), cfg.compiler_profile)
        if path.is_file():
            key = _library_key(spec)
            if key in ambiguous:
                continue
            if key in archives and archives[key] != path:
                # The map's bare library name cannot choose between archives.
                archives.pop(key)
                ambiguous.add(key)
            else:
                archives[key] = path
    return archives


def _common_definitions(
    archive: Path, selected: set[str], names: set[str], static_names: set[str] | None = None
) -> dict[str, list[str]]:
    """Data definitions in the archive members this map demonstrably selected."""
    import lief

    from rebrew.archives import parse_archive

    found: dict[str, list[str]] = {}
    for member, body in parse_archive(str(archive)):
        basename = PureWindowsPath(member).name
        if basename.casefold() not in selected:
            continue
        obj = lief.COFF.parse(list(body))
        if obj is None:
            continue
        for symbol in obj.symbols:
            if symbol.complex_type == lief.COFF.Symbol.COMPLEX_TYPE.FUNCTION:
                continue
            if symbol.name not in names or (
                symbol.storage_class != lief.COFF.Symbol.STORAGE_CLASS.EXTERNAL
                and symbol.name not in (static_names or set())
            ):
                continue
            # A zero-valued undefined symbol is a reference. Nonzero COMMON
            # size, or a real section definition, owns storage in this member.
            if symbol.section_idx > 0 or (symbol.section_idx == 0 and symbol.value > 0):
                bucket = found.setdefault(symbol.name, [])
                if basename not in bucket:
                    bucket.append(basename)
    return found


def enrich_library_owners(
    scan: ScanResult, cfg: ProjectConfig, link_map: Path | None = None
) -> None:
    """Attach proven library owners from the raw link's map or an explicit map.

    Missing automatic maps leave owners unknown. Explicit missing/unreadable maps
    raise OSError. Only exact C/link symbol spellings are matched; never infer an
    owner from a header name, CRT-looking prefix, or a reference VA coincidence.
    """
    for entry in scan.globals.values():
        entry.library_owners.clear()
        entry.generated_owners.clear()
    import lief

    binary = getattr(cfg, "target_binary", None)
    if binary and Path(binary).is_file() and getattr(cfg, "binary_format", "pe") == "pe":
        image = lief.PE.parse(str(binary))
        if image is not None:
            imports: dict[int, str] = {}
            for import_library in image.imports:
                library_name = import_library.name
                if isinstance(library_name, bytes):
                    library_name = library_name.decode("utf-8", errors="replace")
                for item in import_library.entries:
                    name = item.name
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")
                    imports[int(image.optional_header.imagebase) + item.iat_address] = (
                        f"linker:{library_name}!{name or '#' + str(item.ordinal)}"
                    )
            for entry in scan.globals.values():
                if entry.va in imports and entry.storage_kind != "span":
                    entry.storage_kind = "import"
                    entry.generated_owners.append(imports[entry.va])
    if link_map is None:
        raw = getattr(cfg, "raw_link", None)
        if raw is None:
            resolve_backing_owners(scan)
            return
        link_map = Path(raw).with_suffix(".map")
        if not link_map.is_file():
            resolve_backing_owners(scan)
            return
    map_bytes = link_map.read_bytes()
    rows = parse_link_map(map_bytes.decode("utf-8", errors="surrogateescape"))
    map_hash = hashlib.sha256(map_bytes).hexdigest()
    symbols: dict[str, LinkSymbol | None] = {}
    for row in rows:
        if row.is_function:
            continue
        if row.name in symbols and symbols[row.name] != row:
            # Colliding static/public names cannot be resolved by spelling.
            symbols[row.name] = None
        else:
            symbols[row.name] = row
    selected: dict[str, set[str]] = {}
    for row in rows:
        if row.library:
            selected.setdefault(_library_key(row.library), set()).add(row.member.casefold())
    library_names = {_library_key(row.library): row.library for row in rows if row.library}
    common_names = {row.name for row in rows if row.common}
    explicit_names = {entry.link_symbol for entry in scan.globals.values() if entry.link_symbol}
    common: dict[str, list[tuple[str, str, str]]] = {}
    for library, archive in _cached_archives(cfg).items():
        members = selected.get(library, set())
        if not members or not (common_names | explicit_names):
            continue
        try:
            definitions = _common_definitions(
                archive, members, common_names | explicit_names, explicit_names
            )
        except (OSError, ValueError, RuntimeError) as exc:
            log.warning("cannot read data ownership from %s: %s", archive, exc)
            continue
        archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        for name, defining_members in definitions.items():
            common.setdefault(name, []).extend(
                (library_names[library], member, archive_hash) for member in defining_members
            )
    # Compile commands resolve a selected project object to its source even
    # when that source lives outside the reversed-source root. Ambiguity stays
    # unresolved; a basename alone does not choose between two source files.
    source_objects: dict[str, set[Path]] = {}
    compilation_db = link_map.parent / "compile_commands.json"
    if compilation_db.is_file():
        try:
            commands = json.loads(compilation_db.read_text())
            for command in commands:
                source = Path(command["file"])
                if not source.is_absolute():
                    source = Path(command["directory"]) / source
                source_objects.setdefault(source.name.casefold() + ".obj", set()).add(source)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.warning("cannot resolve data object sources from %s: %s", compilation_db, exc)
    function_symbols = {row.name for row in rows if row.is_function}
    for entry in scan.globals.values():
        spellings = ["_" + entry.name, entry.name] if cfg.arch == "x86_32" else [entry.name]
        if entry.link_symbol:
            spellings = [entry.link_symbol]
        if any(name in function_symbols for name in spellings):
            continue
        linked = next((symbols[name] for name in spellings if name in symbols), None)
        if linked is None:
            providers = common.get(entry.link_symbol, []) if entry.link_symbol else []
            if len(providers) == 1:
                library, member, archive_hash = providers[0]
                entry.library_owners.append(
                    {
                        "symbol": entry.link_symbol,
                        "library": library,
                        "member": member,
                        "map": str(link_map),
                        "map_hash": map_hash,
                        "archive_hash": archive_hash,
                        "evidence": "link-map+archive-symbol",
                    }
                )
            continue
        evidence = {
            "symbol": linked.name,
            "linked_va": f"0x{linked.va:08x}",
            "map": str(link_map),
            "map_hash": map_hash,
        }
        if linked.library:
            entry.library_owners.append(
                {
                    **evidence,
                    "library": linked.library,
                    "member": linked.member,
                    "evidence": "link-map",
                }
            )
        elif linked.object and not entry.defined_in:
            source_candidates = source_objects.get(
                PureWindowsPath(linked.object).name.casefold(), set()
            )
            if len(source_candidates) == 1:
                source_path = next(iter(source_candidates))
                from rebrew.c_parser import find_variable_roles
                from rebrew.utils import read_source_text, rel_display_path

                try:
                    source_definitions, _, _ = find_variable_roles(read_source_text(source_path)[0])
                except OSError:
                    source_definitions = set()
                display = rel_display_path(source_path, cfg.reversed_dir)
                if entry.name in source_definitions:
                    entry.defined_in.append(display)
                elif entry.link_symbol:
                    entry.generated_owners.append(
                        f"{display} (compiler literal)"
                        if entry.storage_kind == "literal"
                        else f"{display}:{linked.name}"
                    )
            elif entry.link_symbol:
                entry.generated_owners.append(f"{linked.object}:{linked.name}")
        elif linked.common:
            candidates = common.get(linked.name, [])
            # Several selected COMMON providers may be coalesced. The map did
            # not identify a unique provider, so do not pick the first one.
            if len(candidates) == 1:
                library, member, archive_hash = candidates[0]
                entry.library_owners.append(
                    {
                        **evidence,
                        "library": library,
                        "member": member,
                        "evidence": "link-map+archive",
                        "archive_hash": archive_hash,
                    }
                )

    resolve_backing_owners(scan)


def resolve_backing_owners(scan: ScanResult) -> None:
    """Propagate owners through explicit backing relationships, leaving cycles unknown."""
    # Aliases inherit the backing object's owner without claiming another
    # definition. Resolve chains conservatively and leave cycles unresolved.
    for _ in range(len(scan.globals)):
        changed = False
        for entry in scan.globals.values():
            if not entry.backing or entry.generated_owners:
                continue
            backing = scan.globals.get(entry.backing)
            if backing is None or backing is entry:
                continue
            owners = [
                *backing.defined_in,
                *backing.generated_owners,
                *(f"{owner['library']}:{owner['member']}" for owner in backing.library_owners),
            ]
            if owners:
                entry.generated_owners.extend(f"{owner} (via {entry.backing})" for owner in owners)
                changed = True
        if not changed:
            break
