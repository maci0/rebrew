"""rename_ops.py - Plan and apply project-wide C renames.

Reusable rename engine shared by the ``rebrew source rename`` CLI and library
callers (BinSync import). A rename is planned in full before anything is
written: every source edit (file, line, column), every metadata row change,
and an optional file move. :func:`apply_rename_plan` then writes the sources
(restoring them all if one write fails), moves the file, and updates the
function and data stores through their locked writers.

Three kinds of name are renamed:

- ordinary symbols (functions and globals), with the module rules below;
- types (struct/union/enum tags and typedef names);
- members of one struct or union.

Module rules for ordinary symbols: one ``.c`` definition is one symbol, so
every metadata row in any module bound to that definition (same file, same C
name) is renamed with it. A row-level rename that would carry rows of other
modules along refuses unless the caller acknowledges them (``all_modules``).
Independent definitions of the same name in other files (per-target twins)
keep their name and their references unless ``all_modules`` renames them too.
A reference that cannot be attributed to one definition (a common header, a
file compiled into both) refuses the rename before any write.
"""

from __future__ import annotations

import copy
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rebrew.c_rename import (
    ORDINARY_ROLES,
    ROLE_CODE,
    ROLE_COMMENT,
    ROLE_IDENT,
    ROLE_MACRO,
    ROLE_MACRO_NAME,
    ROLE_TAG,
    ROLE_TYPENAME,
    ParsedSource,
    TypeIndex,
    declares_ordinary,
    definitions,
    file_scope_type,
    member_sites,
    name_regex,
    non_external_function_declarations,
    occurrences,
    rewrite,
)
from rebrew.config import ProjectConfig
from rebrew.errors import RebrewError
from rebrew.function_providers import bind_library_source
from rebrew.metadata.annotation import (
    FUNC_NAME_HINT_RE,
    FUNCTION_MARKERS,
    NEW_FUNC_CAPTURE_RE,
    NEW_KV_RE,
    Annotation,
    parse_c_file_multi,
)
from rebrew.sources import iter_sources_and_headers
from rebrew.utils import atomic_write_text, is_safe_c_ident, read_source_text

logger = logging.getLogger(__name__)

# MSVC ``@N`` suffix. Vectorcall is ``name@@N`` and fastcall is ``@name@N``;
# stripping one ``@N`` is not enough to rebuild either spelling.
_AT_DECORATION_RE = re.compile(r"@\d+$")

#: C89 keywords: valid identifier shapes that are not names.
C_KEYWORDS = frozenset(
    {
        "auto",
        "break",
        "case",
        "char",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "float",
        "for",
        "goto",
        "if",
        "int",
        "long",
        "register",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
    }
)

#: Rename kinds a plan carries.
KIND_FUNCTION = "function"
KIND_DATA = "data"
KIND_TYPE = "type"
KIND_FIELD = "field"

#: Collision report: at most this many sites are named.
_COLLISION_SITE_LIMIT = 5

_HEADER_SUFFIX = ".h"


def redecorated_symbol(old_sym: str, new_name: str, *, underscore: bool | None = None) -> str:
    """Keep MSVC decoration when the C name changes.

    ``_old@12`` stays ``_new@12``. ``old@@12`` stays ``new@@12``.
    ``@old@4`` stays ``@new@4``.

    ``underscore=True`` is the cdecl ``_`` the rename JSON reports. Leaving it
    None copies whether *old_sym* already had one.
    """
    suffix = _AT_DECORATION_RE.search(old_sym)
    tail = suffix.group(0) if suffix else ""
    body = old_sym[: suffix.start()] if suffix else old_sym
    if body.endswith("@"):
        return f"{new_name}@{tail}"
    if body.startswith("@") and not body.startswith("@@"):
        return f"@{new_name}{tail}"
    if underscore is None:
        underscore = old_sym.startswith("_")
    return f"{'_' if underscore else ''}{new_name}{tail}"


def c_name_from_symbol(symbol: str) -> str:
    """C identifier inside an MSVC decorated symbol.

    ``_foo`` and ``_foo@8`` are ``foo``. ``foo@@12`` is ``foo``.
    ``@foo@4`` is ``foo``. One leading underscore is the cdecl
    decoration; ``__foo`` is the function ``_foo``.
    """
    name = symbol[1:] if symbol.startswith("_") else symbol
    name = _AT_DECORATION_RE.sub("", name)
    if name.endswith("@"):
        name = name[:-1]
    elif name.startswith("@") and not name.startswith("@@"):
        name = name[1:]
    return name


def rename_source_name(old_name: str, old_sym: str) -> str:
    """C name a rename searches for.

    A leading ``_`` is cdecl or stdcall decoration. ``hook@@12`` and
    ``@keeps@4`` have none, so an empty stored name still names the function.
    """
    if old_sym and (old_sym.startswith("_") or not old_name):
        return c_name_from_symbol(old_sym)
    return c_name_from_symbol(old_name) if old_name else old_name


def is_valid_new_name(name: str) -> bool:
    """A C89 identifier that is not a keyword."""
    return is_safe_c_ident(name) and name not in C_KEYWORDS


class RenameError(RebrewError, RuntimeError):
    """A rename was refused or could not be completed.

    Raised before any write when a source cannot be read, a reference cannot
    be attributed to one definition, the new name collides, or rows of other
    modules would follow without acknowledgement; and after a failed write,
    once the sources already written are restored. ``files`` carries the
    offending paths so the caller can name them.
    """

    _STRUCTURED_FIELDS = (*RebrewError._STRUCTURED_FIELDS, "files")

    def __init__(self, message: str, *, files: Sequence[Path]) -> None:
        super().__init__(message)
        self.files = list(files)


# ---------------------------------------------------------------------------
# Plan model
# ---------------------------------------------------------------------------


@dataclass
class SourceEdit:
    """One rewritten occurrence."""

    line: int
    column: int
    role: str


@dataclass
class FileChange:
    """A source file and the text it gets."""

    path: Path
    old_text: str
    new_text: str
    encoding: str
    edits: list[SourceEdit]


@dataclass
class RowChange:
    """A metadata row and the fields it gets (``store`` is ``function`` or ``data``)."""

    store: str
    module: str
    va: int
    old: dict[str, Any]
    new: dict[str, Any]


@dataclass
class RenamePlan:
    """Everything one rename writes, computed before any write."""

    kind: str
    old_name: str
    new_name: str
    files: list[FileChange] = field(default_factory=list)
    rows: list[RowChange] = field(default_factory=list)
    move: tuple[Path, Path] | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self, root: Path | None) -> dict[str, Any]:
        """JSON-ready change list; paths relative to *root* when given."""
        from rebrew.utils import rel_display_path

        def show(path: Path) -> str:
            return rel_display_path(path, root) if root is not None else str(path)

        return {
            "kind": self.kind,
            "old_name": self.old_name,
            "new_name": self.new_name,
            "files": [
                {
                    "file": show(change.path),
                    "edits": [
                        {"line": e.line, "column": e.column, "role": e.role} for e in change.edits
                    ],
                }
                for change in self.files
            ],
            "rows": [
                {
                    "store": row.store,
                    "module": row.module,
                    "va": f"0x{row.va:08x}",
                    "old": row.old,
                    "new": row.new,
                }
                for row in self.rows
            ],
            "move": [show(self.move[0]), show(self.move[1])] if self.move else None,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Project sources
# ---------------------------------------------------------------------------


class _Project:
    """Every source and header of one rename, read and parsed at most once."""

    def __init__(self, cfg: ProjectConfig, first: Sequence[Path] = ()) -> None:
        from rebrew.metadata.functions import load_metadata

        self.cfg = cfg
        library_sources: list[Path] = []
        if getattr(cfg, "root", None) is not None:
            # Include every target's providers so an independent vendor twin still collides.
            for (module, va), row in load_metadata(self.metadata_dir, deepcopy=False).items():
                if row.get("marker_type") == "LIBRARY":
                    entry = bind_library_source(
                        cfg, Annotation(module=module, va=va, marker_type="LIBRARY"), row
                    )
                    if entry.filepath:
                        library_sources.append((Path(cfg.reversed_dir) / entry.filepath).resolve())
        seen: set[Path] = set()
        self.paths: list[Path] = []
        for path in [*first, *iter_sources_and_headers(cfg.reversed_dir, cfg), *library_sources]:
            key = path.resolve()
            if key not in seen:
                seen.add(key)
                self.paths.append(path)
        self.texts: dict[Path, tuple[str, str, bytes]] = {}
        unreadable: list[Path] = []
        for path in self.paths:
            try:
                text, encoding = read_source_text(path)
            except (OSError, UnicodeDecodeError):
                unreadable.append(path)
                continue
            self.texts[path] = (text, encoding, text.encode("utf-8", errors="surrogateescape"))
        if unreadable:
            listed = ", ".join(str(p) for p in unreadable)
            raise RenameError(
                f"cannot plan the rename: these sources could not be read, so a "
                f"reference to the old name may be left behind: {listed}. Fix the "
                f"permissions (or encoding) and re-run.",
                files=unreadable,
            )
        self._parsed: dict[Path, ParsedSource] = {}
        self._annotations: dict[Path, list[Annotation]] = {}
        self._data_rows: dict[tuple[str, int], dict[str, Any]] | None = None

    @property
    def metadata_dir(self) -> Path:
        return Path(getattr(self.cfg, "metadata_dir", None) or self.cfg.reversed_dir)

    def containing(self, name: str) -> list[Path]:
        pattern = name_regex(name)
        return [p for p in self.paths if pattern.search(self.texts[p][2])]

    def parsed(self, path: Path) -> ParsedSource:
        if path not in self._parsed:
            self._parsed[path] = ParsedSource.parse(self.texts[path][0])
        return self._parsed[path]

    def annotations(self, path: Path) -> list[Annotation]:
        if path not in self._annotations:
            self._annotations[path] = _rename_annotations(self.cfg, path)
        return self._annotations[path]

    def data_rows(self) -> dict[tuple[str, int], dict[str, Any]]:
        if self._data_rows is None:
            from rebrew.metadata.data import load_data_metadata

            self._data_rows = load_data_metadata(self.metadata_dir)
        return self._data_rows

    def stored_file(self, path: Path) -> str:
        from rebrew.metadata.functions import identity_file

        return identity_file(path, self.metadata_dir)

    def path_for_stored(self, stored: str) -> Path | None:
        """The project path a row's ``file`` names, when it is one of ours."""
        from rebrew.metadata.functions import stored_file_matches

        if not stored:
            return None
        for path in self.paths:
            if stored_file_matches(stored, self.stored_file(path)):
                return path
        return None

    def modules(self, path: Path) -> frozenset[str] | None:
        """Modules whose rows bind *path*; ``None`` for a header or a row-less file."""
        from rebrew.metadata.functions import stored_file_matches
        from rebrew.utils import preset_module_key

        if path.suffix.lower() == _HEADER_SUFFIX:
            return None
        mods = {preset_module_key(e.module) for e in self.annotations(path) if e.module}
        rel = self.stored_file(path)
        mods.update(
            preset_module_key(module)
            for (module, _va), row in self.data_rows().items()
            if stored_file_matches(str(row.get("file") or ""), rel)
        )
        return frozenset(mods) or None


def _rename_annotations(cfg: ProjectConfig, path: Path) -> list[Annotation]:
    """Read every target's identities, including mixed migrated/inline files."""
    from rebrew.metadata.functions import load_metadata

    metadata_dir = getattr(cfg, "metadata_dir", path.parent)
    parsed = parse_c_file_multi(path, metadata_dir=metadata_dir)
    by_identity = {(e.module, e.va, e.marker_type): e for e in parsed}
    for module in {m for m, _va in load_metadata(metadata_dir, deepcopy=False)}:
        for e in parse_c_file_multi(path, target_name=module, metadata_dir=metadata_dir):
            by_identity[(e.module, e.va, e.marker_type)] = e
    return list(by_identity.values())


def _file_change(
    project: _Project, path: Path, spans: list[tuple[int, int, int, int, str]], new: str
) -> FileChange | None:
    if not spans:
        return None
    src = project.parsed(path)
    text, encoding, _data = project.texts[path]
    return FileChange(
        path=path,
        old_text=text,
        new_text=rewrite(src, [(s, e) for s, e, _l, _c, _r in spans], new),
        encoding=encoding,
        edits=[SourceEdit(line, col, role) for _s, _e, line, col, role in spans],
    )


def _sites(paths: list[tuple[Path, int]], root: Path | None) -> str:
    from rebrew.utils import rel_display_path

    shown = [
        f"{rel_display_path(p, root) if root else p}:{line}"
        for p, line in paths[:_COLLISION_SITE_LIMIT]
    ]
    if len(paths) > _COLLISION_SITE_LIMIT:
        shown.append(f"and {len(paths) - _COLLISION_SITE_LIMIT} more")
    return ", ".join(shown)


def _root(cfg: ProjectConfig) -> Path | None:
    root = getattr(cfg, "root", None)
    return Path(root) if root else None


def _ordinary_collisions(project: _Project, new_name: str) -> list[tuple[Path, int]]:
    """Sites where *new_name* already names something in the ordinary namespace."""
    roles = ORDINARY_ROLES | {ROLE_MACRO_NAME}
    return [
        (path, occ.line)
        for path in project.containing(new_name)
        for occ in occurrences(project.parsed(path), new_name)
        if occ.role in roles
    ]


def _row_name_collisions(
    project: _Project, new_name: str, modules: set[str] | None = None
) -> list[str]:
    """``MODULE.0xVA`` of every function or data row already named *new_name*.

    With *modules*, only rows of those modules count: each module links its
    own image, so a row of another module with that name is not a duplicate.
    A shared source definition is caught by the source-level check instead.
    """
    from rebrew.metadata.functions import load_metadata

    def counted(module: str) -> bool:
        return modules is None or module in modules

    taken = [
        f"{module}.0x{va:08x}"
        for (module, va), row in load_metadata(project.metadata_dir, deepcopy=False).items()
        if counted(module)
        and (
            row.get("name") == new_name
            or (row.get("symbol") and c_name_from_symbol(str(row["symbol"])) == new_name)
        )
    ]
    taken += [
        f"{module}.0x{va:08x}"
        for (module, va), row in project.data_rows().items()
        if counted(module) and row.get("name") == new_name
    ]
    return taken


# ---------------------------------------------------------------------------
# Ordinary symbols: functions and globals
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Selection:
    """The row a rename starts from (absent for a source-level rename)."""

    store: str
    module: str
    va: int


def _linker_reference_changes(
    cfg: ProjectConfig, symbols: dict[str, dict[str, str]]
) -> list[FileChange]:
    """Plan exact MSVC symbol references in each affected target's layout response files."""
    from rebrew.config import load_config
    from rebrew.utils import preset_module_key

    root = _root(cfg)
    if root is None or not symbols or not (root / "layout").is_dir():
        return []
    names = getattr(cfg, "all_targets", [])
    targets = [load_config(root, target=name) for name in names] if names else [cfg]
    pattern = re.compile(r'(?<!\S)/(INCLUDE|ALTERNATENAME|EXPORT):("[^"\r\n]*"|[^\s"]+)', re.I)
    changes = []
    for target in targets:
        mapping = {
            old: new
            for module, names in symbols.items()
            if preset_module_key(module) == preset_module_key(target.marker)
            for old, new in names.items()
        }
        if not mapping:
            continue
        directory = root / "layout" / (target.target_name or target.target_binary.name)
        for path in sorted(directory.rglob("*.rsp")):
            if not path.resolve().is_relative_to(root.resolve()):
                raise RenameError("linker response file escapes the project", files=[path])
            try:
                text, encoding = read_source_text(path)
            except (OSError, UnicodeDecodeError) as exc:
                raise RenameError("cannot read linker response file", files=[path]) from exc
            edits: list[SourceEdit] = []

            def replace(
                match: re.Match[str],
                *,
                mapping: dict[str, str] = mapping,
                text: str = text,
                edits: list[SourceEdit] = edits,
            ) -> str:
                """Change internal symbols while preserving export names and other options."""
                option, value = match.groups()
                quote = '"' if value.startswith('"') else ""
                body = value[1:-1] if quote else value
                binding, separator, qualifiers = body.partition(",")
                if option.upper() == "INCLUDE":
                    updated = mapping.get(binding, binding)
                elif option.upper() == "ALTERNATENAME":
                    updated = "=".join(mapping.get(part, part) for part in binding.split("="))
                elif "=" in binding:
                    public, internal = binding.split("=", 1)
                    updated = public + "=" + mapping.get(internal, internal)
                elif binding in mapping:
                    updated = binding + "=" + mapping[binding]
                else:
                    updated = binding
                if updated == binding:
                    return match.group()
                offset = match.start(2)
                edits.append(
                    SourceEdit(
                        text.count("\n", 0, offset) + 1,
                        offset - text.rfind("\n", 0, offset),
                        "linker",
                    )
                )
                return "/" + option + ":" + quote + updated + separator + qualifiers + quote

            updated = pattern.sub(replace, text)
            if edits:
                changes.append(FileChange(path, text, updated, encoding, edits))
    return changes


def plan_function_reference_binding(
    cfg: ProjectConfig, old_name: str, selected: Selection, *, comments: bool = False
) -> RenamePlan:
    """Bind an unbound source name to an external definition or library identity.

    The explicit destination identity asserts that the placeholder's references
    mean this function. Its definition, identity and verification are unchanged.
    """
    from rebrew.metadata.annotation import parse_library_header
    from rebrew.metadata.functions import get_entry

    if selected.store != KIND_FUNCTION or not is_valid_new_name(old_name):
        raise ValueError("function reference binding requires an unbound C function name")
    project = _Project(cfg)
    row = get_entry(project.metadata_dir, selected.va, selected.module)
    new_name = rename_source_name(str(row.get("name") or ""), str(row.get("symbol") or ""))
    destination = project.path_for_stored(str(row.get("file") or ""))
    if destination is None or not is_valid_new_name(new_name):
        raise RenameError("binding destination has no project function definition", files=[])
    defs = {p: definitions(project.parsed(p), new_name) for p in project.containing(new_name)}
    found_defs = [(p, d.kind, d.static) for p, found in defs.items() for d in found]
    library_identity = (
        row.get("marker_type") == "LIBRARY"
        and destination.suffix.lower() == ".h"
        and destination.is_file()
        and any(
            e.module == selected.module and e.va == selected.va and e.symbol == row.get("symbol")
            for e in parse_library_header(destination, metadata_dir=project.metadata_dir)
        )
    )
    if not (library_identity and not found_defs) and found_defs != [
        (destination, "function", False)
    ]:
        raise RenameError(
            "binding destination must have one external function definition", files=list(defs)
        )
    if old_name == new_name or _row_name_collisions(project, old_name):
        raise RenameError("binding source must be an unbound placeholder", files=[])
    hits = project.containing(old_name)
    if any(
        rename_source_name(e.name, e.symbol) == old_name
        for path in hits
        for e in [
            *project.annotations(path),
            *parse_library_header(path, metadata_dir=project.metadata_dir),
        ]
    ):
        raise RenameError("binding source already has a function identity", files=hits)
    for name, paths in ((old_name, hits), (new_name, list(dict.fromkeys([destination, *hits])))):
        invalid = [
            p
            for p in paths
            if non_external_function_declarations(project.parsed(p), name)
            or any(o.role == ROLE_MACRO_NAME for o in occurrences(project.parsed(p), name))
            or (name == old_name and definitions(project.parsed(p), name))
        ]
        if invalid:
            raise RenameError(
                f"cannot bind {name}: it declares a definition, variable, type, static or macro",
                files=invalid,
            )
    plan = RenamePlan(kind=KIND_FUNCTION, old_name=old_name, new_name=new_name)
    roles = ORDINARY_ROLES | ({ROLE_COMMENT} if comments else set())
    for path in hits:
        spans = [
            (o.start, o.end, o.line, o.column, o.role)
            for o in occurrences(project.parsed(path), old_name)
            if o.role in roles
        ]
        change = _file_change(project, path, spans, new_name)
        if change is not None:
            plan.files.append(change)
    symbol = str(row.get("symbol") or "_" + new_name)
    plan.files.extend(
        _linker_reference_changes(
            cfg, {selected.module: {redecorated_symbol(symbol, old_name): symbol}}
        )
    )
    if not plan.files:
        raise RenameError(f"no function references to {old_name} were found", files=[])
    plan.notes.append(
        f"References bound to {selected.module}.0x{selected.va:08x}; identity unchanged"
    )
    return plan


def plan_symbol_rename(
    cfg: ProjectConfig,
    old_name: str,
    new_name: str,
    *,
    store: str,
    selected: Selection | None = None,
    definition_file: Path | None = None,
    all_modules: bool = False,
    comments: bool = False,
    require_ack: bool = True,
    rename_file: bool = False,
    new_filename: str | None = None,
    dry_run: bool = False,
) -> RenamePlan:
    """Plan renaming the function or global *old_name* to *new_name*.

    *definition_file* is the selected row's source; without it the unique
    definition in the project is renamed. *require_ack* refuses rows of
    modules other than *selected*'s unless *all_modules* is set.
    """
    if not old_name:
        raise ValueError("cannot rename: the old name is empty (no marker, name or symbol)")
    if not is_valid_new_name(new_name):
        raise ValueError(f"target name {new_name!r} is not a valid C identifier")
    if definition_file is not None and not dry_run:
        read_source_text(definition_file)  # a missing definition is reported as itself
    project = _Project(cfg, [definition_file] if definition_file is not None else [])
    kind = KIND_DATA if store == KIND_DATA else KIND_FUNCTION
    plan = RenamePlan(kind=kind, old_name=old_name, new_name=new_name)

    hits = project.containing(old_name)
    defs = {p: definitions(project.parsed(p), old_name) for p in hits}
    external = {p for p, found in defs.items() if any(not d.static for d in found)}
    statics = {p for p, found in defs.items() if found and all(d.static for d in found)}

    if definition_file is not None and definition_file in statics:
        chosen: set[Path] = {definition_file}
        rename_set = {definition_file}
    else:
        if all_modules:
            chosen = set(external)
        elif definition_file is not None and definition_file in external:
            chosen = {definition_file}
        elif len(external) <= 1:
            chosen = set(external)
        else:
            raise RenameError(
                f"cannot rename {old_name}: {len(external)} files define it; select one "
                "definition by its row (MODULE.0xVA) or pass --all-modules to rename all; "
                "no files were changed",
                files=sorted(external),
            )
        rename_set = set(chosen) | (
            {definition_file} if definition_file is not None and definition_file in hits else set()
        )
        rename_set |= _attributed_references(project, hits, chosen, external - chosen, statics)

    for path in sorted(rename_set, key=str):
        roles = ORDINARY_ROLES | ({ROLE_COMMENT} if comments else set())
        spans = [
            (o.start, o.end, o.line, o.column, o.role)
            for o in occurrences(project.parsed(path), old_name)
            if o.role in roles
        ]
        change = _file_change(project, path, spans, new_name)
        if change is not None:
            plan.files.append(change)

    _plan_symbol_rows(project, plan, chosen, rename_set, selected, store)
    _check_acknowledged(plan, selected, all_modules=all_modules, require_ack=require_ack)

    collisions = _ordinary_collisions(project, new_name)
    if collisions:
        raise RenameError(
            f"cannot rename {old_name} to {new_name}: {new_name} is already used at "
            f"{_sites(collisions, _root(cfg))}; renaming would create a duplicate symbol; "
            "no files were changed",
            files=sorted({p for p, _line in collisions}),
        )
    renamed_modules = {row.module for row in plan.rows} | (
        {selected.module} if selected is not None else set()
    )
    taken = _row_name_collisions(project, new_name, renamed_modules or None)
    if taken:
        raise RenameError(
            f"cannot rename {old_name} to {new_name}: rows already use {new_name} "
            f"({', '.join(taken[:_COLLISION_SITE_LIMIT])}); renaming would create a "
            "duplicate symbol; no files were changed",
            files=[],
        )

    if rename_file and store == KIND_FUNCTION and definition_file is not None:
        _plan_file_move(project, plan, definition_file, old_name, new_name, new_filename)
    symbols: dict[str, dict[str, str]] = {}
    for row in plan.rows:
        if "name" not in row.new:
            continue
        old = str(row.old.get("symbol") or row.old.get("link_symbol") or "_" + old_name)
        new = str(
            row.new.get("symbol") or row.new.get("link_symbol") or redecorated_symbol(old, new_name)
        )
        symbols.setdefault(row.module, {})[old] = new
    plan.files.extend(_linker_reference_changes(cfg, symbols))
    return plan


def _attributed_references(
    project: _Project,
    hits: list[Path],
    chosen: set[Path],
    others: set[Path],
    statics: set[Path],
) -> set[Path]:
    """Reference files that belong to the chosen definitions.

    Raises :class:`RenameError` for a file that cannot be attributed: a header
    or row-less file while another definition exists, or a file whose modules
    link both the chosen and an independent definition.
    """

    def union(paths: set[Path]) -> frozenset[str] | None:
        """Modules building *paths*; None when one may be built into every module."""
        mods: set[str] = set()
        for path in paths:
            found = project.modules(path)
            if found is None:
                return None
            mods |= found
        return frozenset(mods)

    chosen_mods = union(chosen) if chosen else None
    other_mods = union(others) if others else frozenset()

    def meets(mods: frozenset[str], group: frozenset[str] | None) -> bool:
        return group is None or bool(mods & group)

    selected: set[Path] = set()
    ambiguous: list[Path] = []
    for path in hits:
        if path in chosen or path in others or path in statics:
            continue
        if not others:
            selected.add(path)
            continue
        mods = project.modules(path)
        if mods is None:
            ambiguous.append(path)
            continue
        ours, theirs = meets(mods, chosen_mods), meets(mods, other_mods)
        if ours and not theirs:
            selected.add(path)
        elif theirs and not ours:
            continue
        else:
            ambiguous.append(path)
    if ambiguous:
        raise RenameError(
            "cannot rename: ambiguous references to independent target symbols "
            "(a common header or a file built into targets that link different "
            "definitions); separate or annotate their ownership, or pass "
            "--all-modules to rename every definition; no files were changed",
            files=sorted(ambiguous),
        )
    return selected


def _plan_symbol_rows(
    project: _Project,
    plan: RenamePlan,
    chosen: set[Path],
    rename_set: set[Path],
    selected: Selection | None,
    store: str,
) -> None:
    """Function and data rows bound to the renamed symbol, plus left-alone notes."""
    from rebrew.metadata.functions import load_metadata

    old, new = plan.old_name, plan.new_name
    function_rows = load_metadata(project.metadata_dir, deepcopy=False)
    bound: set[tuple[str, int]] = set()
    for path in sorted(chosen, key=str):
        for entry in project.annotations(path):
            if entry.marker_type not in FUNCTION_MARKERS:
                continue
            if entry.name != old and c_name_from_symbol(entry.symbol or "") != old:
                continue
            bound.add((entry.module, entry.va))
            stored = function_rows.get((entry.module, entry.va), {})
            if not stored.get("file"):
                continue  # an inline marker follows its rewritten source
            symbol = str(stored.get("symbol") or entry.symbol or "")
            new_fields = {"name": new}
            old_fields = {"name": str(stored.get("name") or entry.name or "")}
            if symbol:
                new_fields["symbol"] = redecorated_symbol(symbol, new)
                old_fields["symbol"] = symbol
            plan.rows.append(RowChange("function", entry.module, entry.va, old_fields, new_fields))
    for (module, va), row in function_rows.items():
        if (module, va) in bound:
            continue
        symbol = str(row.get("symbol") or "")
        if row.get("name") == old or (symbol and c_name_from_symbol(symbol) == old):
            plan.notes.append(
                f"left {module}.0x{va:08x} ({row.get('file') or 'no file'}): "
                "bound to another definition"
            )
    written = rename_set | {c.path for c in plan.files}
    for (module, va), row in sorted(project.data_rows().items()):
        if row.get("name") != old:
            continue
        row_path = project.path_for_stored(str(row.get("file") or ""))
        is_selected = selected is not None and (selected.store, selected.module, selected.va) == (
            KIND_DATA,
            module,
            va,
        )
        if is_selected or (row_path is not None and row_path in written):
            plan.rows.append(RowChange("data", module, va, *_data_row_names(row, old, new)))
        else:
            plan.notes.append(
                f"left data row {module}.0x{va:08x} ({row.get('file') or 'no file'}): "
                "its file is not rewritten"
            )
    if (
        selected is not None
        and store == KIND_DATA
        and not any((r.module, r.va) == (selected.module, selected.va) for r in plan.rows)
    ):
        row = project.data_rows().get((selected.module, selected.va), {})
        plan.rows.append(
            RowChange("data", selected.module, selected.va, *_data_row_names(row, old, new))
        )


def _data_row_names(
    row: dict[str, Any], old: str, new: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Old and new name fields of a data row: ``name`` plus a ``link_symbol`` spelling *old*.

    ``link_symbol`` is the native symbol the linker emits for the definition
    being renamed, so it follows the C name with its decoration kept.
    """
    old_fields: dict[str, Any] = {"name": old}
    new_fields: dict[str, Any] = {"name": new}
    link = str(row.get("link_symbol") or "")
    if link and c_name_from_symbol(link) == old:
        old_fields["link_symbol"] = link
        new_fields["link_symbol"] = redecorated_symbol(link, new)
    return old_fields, new_fields


_HINT_LINE_RE = re.compile(r"^(?P<lead>\s*//[ \t]?)(?P<text>[^\r\n]*?)[ \t]*(?P<eol>\r?\n?)$")


def is_decorated_symbol(name: str) -> bool:
    """An MSVC-decorated linker name (``?f@@YAXXZ``, ``_f@8``) a header line may carry."""
    match = FUNC_NAME_HINT_RE.match(f"// {name}")
    return match is not None and not is_valid_new_name(name)


def plan_header_row_rename(
    cfg: ProjectConfig, module: str, va: int, new_name: str
) -> RenamePlan | None:
    """Rename a function row that only a header marker names (a library identification).

    Such a row has no C definition: its name is the line under its
    ``// LIBRARY: MODULE 0xVA`` marker. That line and the row are rewritten,
    whatever the line held before (a symbol, prose, or nothing). A C name
    keeps the old symbol's decoration (cdecl ``_`` when the old line was no
    symbol); a decorated *new_name* is both the row's name and its symbol, as
    other C++ library rows store it. Returns None for a row whose file has no
    such marker.
    """
    from rebrew.metadata.functions import load_metadata

    if not (is_valid_new_name(new_name) or is_decorated_symbol(new_name)):
        raise ValueError(f"target name {new_name!r} is neither a C identifier nor a symbol")
    rows = load_metadata(Path(getattr(cfg, "metadata_dir", None) or cfg.reversed_dir))
    stored = rows.get((module, va))
    if not stored or stored.get("marker_type") != "LIBRARY" or not stored.get("file"):
        return None
    path = Path(cfg.root) / str(stored["file"])
    if not path.resolve().is_relative_to(Path(cfg.root).resolve()):
        raise RenameError("library header escapes the project", files=[path])
    if path.suffix.lower() not in {".h", ".hpp"} or not path.is_file():
        return None
    text, encoding = read_source_text(path)
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines[:-1]):
        marker = NEW_FUNC_CAPTURE_RE.search(line)
        if marker is None or marker["module"] != module or int(marker["va"], 16) != va:
            continue
        hint = _HINT_LINE_RE.match(lines[index + 1])
        if hint is None or NEW_FUNC_CAPTURE_RE.search(lines[index + 1]):
            return None
        if NEW_KV_RE.match(lines[index + 1].strip()):
            return None  # the marker has no name line, only KEY: value lines
        old_text = hint["text"]
        if is_decorated_symbol(new_name):
            new_symbol = new_name
        elif FUNC_NAME_HINT_RE.match(f"// {old_text}"):
            new_symbol = redecorated_symbol(old_text, new_name)
        else:
            new_symbol = f"_{new_name}"
        taken = [
            f"{m}.0x{v:08x}"
            for (m, v), row in rows.items()
            if m == module
            and v != va
            and (row.get("name") == new_name or row.get("symbol") == new_symbol)
        ]
        if taken:
            raise RenameError(
                f"cannot rename {module}.0x{va:08x} to {new_name}: rows already use it "
                f"({', '.join(taken[:_COLLISION_SITE_LIMIT])}); renaming would create a "
                "duplicate symbol; no files were changed",
                files=[],
            )
        lines[index + 1] = f"{hint['lead'].rstrip()} {new_symbol}{hint['eol']}"
        name = new_symbol if is_decorated_symbol(new_name) else new_name
        plan = RenamePlan(
            kind=KIND_FUNCTION, old_name=old_text or str(stored.get("name") or ""), new_name=name
        )
        plan.files.append(
            FileChange(
                path=path,
                old_text=text,
                new_text="".join(lines),
                encoding=encoding,
                edits=[SourceEdit(index + 2, len(hint["lead"].rstrip()) + 2, ROLE_COMMENT)],
            )
        )
        plan.rows.append(
            RowChange(
                "function",
                module,
                va,
                {"name": str(stored.get("name") or ""), "symbol": str(stored.get("symbol") or "")},
                {"name": name, "symbol": new_symbol},
            )
        )
        return plan
    return None


def _check_acknowledged(
    plan: RenamePlan, selected: Selection | None, *, all_modules: bool, require_ack: bool
) -> None:
    from rebrew.utils import preset_module_key

    if selected is None or all_modules or not require_ack:
        return
    mine = preset_module_key(selected.module)
    others = [r for r in plan.rows if preset_module_key(r.module) != mine]
    if others:
        listed = ", ".join(f"{r.module}.0x{r.va:08x}" for r in others)
        raise RenameError(
            f"cannot rename {plan.old_name} for {selected.module} alone: its definition is "
            f"shared with rows of other modules ({listed}); pass --all-modules to rename "
            "them with it, or bind those rows to their own definition first; no files "
            "were changed",
            files=sorted({c.path for c in plan.files}),
        )


def _plan_file_move(
    project: _Project,
    plan: RenamePlan,
    filepath: Path,
    old_name: str,
    new_name: str,
    new_filename: str | None,
) -> None:
    """Rename the definition's file when its stem is the old name (or on request)."""
    from rebrew.utils import rel_display_path

    cfg = project.cfg
    metadata_dir = project.metadata_dir
    try:
        multi = len(parse_c_file_multi(filepath, metadata_dir=metadata_dir)) > 1
    except Exception as exc:  # a preview must fail where the write would
        raise ValueError(f"cannot rename {filepath}: annotation parse failed: {exc}") from exc
    if multi and not new_filename:
        return
    if new_filename:
        if Path(new_filename).suffix != filepath.suffix:
            new_filename = new_filename + filepath.suffix
        if "/" in new_filename or "\\" in new_filename:
            candidate = (Path(cfg.reversed_dir) / new_filename).resolve()
            try:
                candidate.relative_to(Path(cfg.reversed_dir).resolve())
            except ValueError as exc:
                raise ValueError(f"new filename escapes reversed_dir: {new_filename!r}") from exc
            target = candidate
        else:
            target = filepath.with_name(new_filename)
    elif filepath.stem == old_name:
        target = filepath.with_name(f"{new_name}{filepath.suffix}")
    else:
        return
    if target == filepath:
        return
    if target.exists():
        raise FileExistsError(
            f"Cannot rename {filepath.name} → {target.name}: target already exists "
            "(different VA). Use --file to pick a different filename."
        )
    plan.move = (filepath, target)
    new_file = rel_display_path(target, getattr(cfg, "root", None) or metadata_dir)
    from rebrew.metadata.functions import load_metadata, stored_file_matches

    function_rows = load_metadata(metadata_dir, deepcopy=False)
    by_key = {(r.store, r.module, r.va): r for r in plan.rows}
    for entry in project.annotations(filepath):
        stored = function_rows.get((entry.module, entry.va), {})
        if not stored.get("file"):
            continue
        row = by_key.get(("function", entry.module, entry.va))
        if row is None:
            row = RowChange("function", entry.module, entry.va, {}, {})
            plan.rows.append(row)
            by_key[("function", entry.module, entry.va)] = row
        row.old["file"] = str(stored["file"])
        row.new["file"] = new_file
    old_file = project.stored_file(filepath)
    for (module, va), data_row in project.data_rows().items():
        if not stored_file_matches(str(data_row.get("file") or ""), old_file):
            continue
        row = by_key.get(("data", module, va))
        if row is None:
            row = RowChange("data", module, va, {}, {})
            plan.rows.append(row)
        row.old["file"] = str(data_row.get("file"))
        row.new["file"] = new_file


# ---------------------------------------------------------------------------
# Types and members
# ---------------------------------------------------------------------------


def _type_index(project: _Project) -> TypeIndex:
    """Records and typedefs of every project source that can define one."""
    index = TypeIndex()
    keyword = re.compile(rb"\b(?:struct|union|enum|typedef)\b")
    for path in project.paths:
        if keyword.search(project.texts[path][2]):
            index.add_source(str(path), project.parsed(path))
    return index


def _replace_word(text: str, old: str, new: str) -> str:
    return re.sub(r"(?<![\w$])" + re.escape(old) + r"(?![\w$])", new, text)


def plan_type_rename(
    cfg: ProjectConfig, old_name: str, new_name: str, *, comments: bool = False
) -> RenamePlan:
    """Plan renaming the struct/union/enum tag or typedef *old_name*."""
    if not is_valid_new_name(new_name):
        raise ValueError(f"target name {new_name!r} is not a valid C identifier")
    project = _Project(cfg)
    index = _type_index(project)
    if old_name not in index.type_names:
        raise RenameError(
            f"cannot rename type {old_name}: no struct, union, enum or typedef has that name",
            files=[],
        )
    plan = RenamePlan(kind=KIND_TYPE, old_name=old_name, new_name=new_name)
    clashes = [
        (path, line)
        for path in project.containing(new_name)
        for line in [
            o.line
            for o in occurrences(project.parsed(path), new_name)
            if o.role in ORDINARY_ROLES | {ROLE_TAG, ROLE_MACRO_NAME}
        ]
    ]
    if new_name in index.type_names or clashes:
        raise RenameError(
            f"cannot rename type {old_name} to {new_name}: {new_name} is already used"
            + (f" at {_sites(clashes, _root(cfg))}" if clashes else " as a type")
            + "; no files were changed",
            files=sorted({p for p, _line in clashes}),
        )
    hits = project.containing(old_name)
    ordinary_decls = [
        (path, line) for path in hits for line in declares_ordinary(project.parsed(path), old_name)
    ]
    typedef = old_name in index.typedef_names
    if typedef and ordinary_decls:
        raise RenameError(
            f"cannot rename type {old_name}: the typedef name is also declared as a function, "
            f"variable or parameter at {_sites(ordinary_decls, _root(cfg))}; rename that "
            "first; no files were changed",
            files=sorted({p for p, _line in ordinary_decls}),
        )
    roles = {ROLE_TAG, ROLE_TYPENAME}
    if not ordinary_decls:
        roles |= {ROLE_IDENT, ROLE_MACRO, ROLE_CODE}
    else:
        plan.notes.append(
            f"left ordinary uses of {old_name}: a function or variable also has that name"
        )
    if comments:
        roles.add(ROLE_COMMENT)
    for path in hits:
        spans = [
            (o.start, o.end, o.line, o.column, o.role)
            for o in occurrences(project.parsed(path), old_name)
            if o.role in roles
        ]
        change = _file_change(project, path, spans, new_name)
        if change is not None:
            plan.files.append(change)

    from rebrew.metadata.functions import load_metadata

    for (module, va), row in sorted(project.data_rows().items()):
        type_text = str(row.get("type") or "")
        if type_text and name_regex(old_name).search(type_text.encode("utf-8")):
            plan.rows.append(
                RowChange(
                    "data",
                    module,
                    va,
                    {"type": type_text},
                    {"type": _replace_word(type_text, old_name, new_name)},
                )
            )
    for (module, va), row in sorted(load_metadata(project.metadata_dir, deepcopy=False).items()):
        local_vars = row.get("locals")
        if not isinstance(local_vars, dict):
            continue
        updated = copy.deepcopy(dict(local_vars))
        changed = False
        for value in updated.values():
            if isinstance(value, dict) and isinstance(value.get("type"), str):
                renamed = _replace_word(value["type"], old_name, new_name)
                changed |= renamed != value["type"]
                value["type"] = renamed
        if changed:
            plan.rows.append(
                RowChange("function", module, va, {"locals": dict(local_vars)}, {"locals": updated})
            )
    if index.keys_named(old_name):
        plan.notes.append(
            f"BinSync: rebrew sync push exports struct.{new_name}; a state dir keeps its "
            f"struct.{old_name} artifact until it is removed there"
        )
    return plan


def plan_field_rename(
    cfg: ProjectConfig, record: str, old_name: str, new_name: str, *, comments: bool = False
) -> RenamePlan:
    """Plan renaming member *old_name* of struct/union *record*."""
    if not is_valid_new_name(new_name):
        raise ValueError(f"target name {new_name!r} is not a valid C identifier")
    project = _Project(cfg)
    index = _type_index(project)
    targets = index.keys_named(record)
    if not targets:
        raise RenameError(
            f"cannot rename {record}.{old_name}: no struct or union {record}", files=[]
        )
    if not any(old_name in index.members[key] for key in targets):
        raise RenameError(
            f"cannot rename {record}.{old_name}: {record} has no member {old_name}", files=[]
        )
    if any(new_name in index.members[key] for key in targets):
        raise RenameError(
            f"cannot rename {record}.{old_name} to {new_name}: {record} already has a member "
            f"{new_name}",
            files=[],
        )
    macro_clash = [
        (path, o.line)
        for path in project.containing(new_name)
        for o in occurrences(project.parsed(path), new_name)
        if o.role == ROLE_MACRO_NAME
    ]
    if macro_clash:
        raise RenameError(
            f"cannot rename {record}.{old_name} to {new_name}: a macro named {new_name} is "
            f"defined at {_sites(macro_clash, _root(cfg))}",
            files=sorted({p for p, _l in macro_clash}),
        )
    unique = not any(
        old_name in members for key, members in index.members.items() if key not in targets
    )
    lookups: dict[str, str | None] = {}

    def lookup(name: str) -> str | None:
        """Record a file-scope name's declarations agree on, each resolved in its file."""
        if name not in lookups:
            keys = {
                index.resolve(token, str(path))
                for path in project.containing(name)
                for token in file_scope_type(project.parsed(path), str(path), name)
            }
            lookups[name] = next(iter(keys)) if len(keys) == 1 else None
        return lookups[name]

    plan = RenamePlan(kind=KIND_FIELD, old_name=f"{record}.{old_name}", new_name=new_name)
    unresolved: list[tuple[Path, int]] = []
    for path in project.containing(old_name):
        src = project.parsed(path)
        sites = member_sites(src, str(path), old_name, targets, index, lookup, unique=unique)
        unresolved += [(path, s.occurrence.line) for s in sites if s.verdict == "unresolved"]
        spans = [
            (o.start, o.end, o.line, o.column, o.role)
            for o in (s.occurrence for s in sites if s.verdict == "rename")
        ]
        if comments:
            spans += [
                (o.start, o.end, o.line, o.column, o.role)
                for o in occurrences(src, old_name)
                if o.role == ROLE_COMMENT
            ]
        change = _file_change(project, path, spans, new_name)
        if change is not None:
            plan.files.append(change)
    if unresolved:
        raise RenameError(
            f"cannot rename {record}.{old_name}: other records also have a member {old_name} "
            f"and these accesses could not be resolved to a type: "
            f"{_sites(unresolved, _root(cfg))}; add a cast or a typed local there; no files "
            "were changed",
            files=sorted({p for p, _l in unresolved}),
        )
    plan.notes.append(
        f"BinSync: rebrew sync push exports the renamed member of struct.{record} from the source"
    )
    return plan


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------


def apply_rename_plan(cfg: ProjectConfig, plan: RenamePlan) -> int:
    """Write *plan*: sources, the optional file move, then the metadata rows.

    Returns the number of source files rewritten. A failed source write or
    move restores every source already written and raises
    :class:`RenameError`; the stores are written only after every source
    landed.
    """
    from rebrew.metadata.source_provenance import (
        SOURCE_PROVENANCE_FILENAME,
        rename_source_provenance,
    )

    metadata_dir = getattr(cfg, "metadata_dir", None) or cfg.reversed_dir
    provenance_edits = {c.path: (c.old_text, c.new_text) for c in plan.files}
    if plan.move and plan.move[0] not in provenance_edits:
        text, _ = read_source_text(plan.move[0])
        provenance_edits[plan.move[0]] = (text, text)
    symbol_rename = (plan.old_name, plan.new_name) if plan.kind == KIND_FUNCTION else None
    try:
        rename_source_provenance(
            metadata_dir,
            provenance_edits,
            symbol_rename=symbol_rename,
            move=plan.move,
            dry_run=True,
        )
    except (OSError, ValueError) as exc:
        raise RenameError(f"source provenance prevents rename: {exc}", files=[]) from exc

    written: list[FileChange] = []
    current: Path | None = None
    moved = False
    try:
        for change in plan.files:
            current = change.path
            atomic_write_text(change.path, change.new_text, encoding=change.encoding)
            written.append(change)
        if plan.move is not None:
            current = plan.move[0]
            plan.move[0].rename(plan.move[1])
            moved = True
        current = Path(metadata_dir) / SOURCE_PROVENANCE_FILENAME
        rename_source_provenance(
            metadata_dir,
            provenance_edits,
            symbol_rename=symbol_rename,
            move=plan.move,
        )
    except (OSError, UnicodeEncodeError, ValueError) as exc:
        if moved and plan.move is not None:
            try:
                plan.move[1].rename(plan.move[0])
            except OSError:
                logger.exception("could not restore %s after a failed rename", plan.move[0])
        for change in reversed(written):
            try:
                atomic_write_text(change.path, change.old_text, encoding=change.encoding)
            except (OSError, UnicodeEncodeError):
                logger.exception("could not restore %s after a failed rename", change.path)
        raise RenameError(
            f"rename of {plan.old_name} to {plan.new_name} failed at {current} ({exc}); "
            "the sources already written were restored and no metadata was changed",
            files=[current] if current is not None else [],
        ) from exc

    function_rows = [
        {
            "module": r.module,
            "va": r.va,
            "identity": {k: v for k, v in r.new.items() if k in ("name", "symbol", "file")},
            "fields": {k: v for k, v in r.new.items() if k not in ("name", "symbol", "file")},
        }
        for r in plan.rows
        if r.store == "function"
    ]
    data_rows = [
        {"module": r.module, "va": r.va, "fields": dict(r.new), "updated_by": "rename"}
        for r in plan.rows
        if r.store == "data"
    ]
    if function_rows:
        from rebrew.metadata.functions import record_migrated_markers

        record_migrated_markers(
            metadata_dir, function_rows, overwrite_name=True, updated_by="rename"
        )
    if data_rows:
        from rebrew.metadata.data import set_data_fields_batch

        set_data_fields_batch(metadata_dir, data_rows)
    return len(written)


def rename_function_everywhere(
    cfg: ProjectConfig,
    filepath: Path,
    old_name: str,
    old_sym: str,
    target_func: str,
    rename_file: bool = True,
    new_filename: str | None = None,
    dry_run: bool = False,
) -> int:
    """Rename the function defined in *filepath* everywhere; returns files changed.

    Library entry point (BinSync import): every row bound to the definition
    follows it, in every module, without acknowledgement. A dry run returns
    the count it would change and writes nothing.
    """
    actual_old_name = rename_source_name(old_name, old_sym)
    if not actual_old_name:
        raise ValueError(
            f"cannot rename {filepath}: old name is empty (missing FUNCTION marker or symbol)"
        )
    plan = plan_symbol_rename(
        cfg,
        actual_old_name,
        target_func,
        store=KIND_FUNCTION,
        definition_file=filepath,
        require_ack=False,
        rename_file=rename_file,
        new_filename=new_filename,
        dry_run=dry_run,
    )
    if dry_run:
        return len(plan.files)
    return apply_rename_plan(cfg, plan)
