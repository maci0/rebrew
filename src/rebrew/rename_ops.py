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

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
lazy import copy
lazy import hashlib
lazy import json
lazy from collections.abc import Sequence

from rebrew.errors import RebrewError
lazy from rebrew.c_rename import (
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
    function_reference_occurrences,
    member_sites,
    name_regex,
    non_external_function_declarations,
    occurrences,
    rewrite,
)
lazy from rebrew.config import ProjectConfig
lazy from rebrew.function_providers import bind_compiled_source
lazy from rebrew.metadata.bindings import (
    FUNCTION_KINDS,
    SourceBinding,
    read_source_bindings,
)
lazy from rebrew.metadata.storage import input_digest, metadata_store_paths
lazy from rebrew.sources import iter_sources_and_headers
lazy from rebrew.utils import atomic_write_text, is_safe_c_ident, read_source_text

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
    reference_owners: dict[Path, Selection] = field(default_factory=dict)
    preserved_references: set[Path] = field(default_factory=set)
    pending_owners: dict[Path, Selection] = field(default_factory=dict)
    input_hashes: dict[str, str] = field(default_factory=dict)

    @property
    def input_digest(self) -> str:
        """Guard the reviewed operation, ownership decisions and exact inputs."""
        payload = {
            "kind": self.kind,
            "old_name": self.old_name,
            "new_name": self.new_name,
            "move": [str(p) for p in self.move] if self.move else None,
            "owners": {str(p): [s.store, s.module, s.va] for p, s in self.reference_owners.items()},
            "preserved_references": sorted(map(str, self.preserved_references)),
            "pending_owners": {
                str(p): [s.store, s.module, s.va] for p, s in self.pending_owners.items()
            },
            "inputs": self.input_hashes,
            "edits": {
                str(c.path): hashlib.sha256(c.new_text.encode(c.encoding)).hexdigest()
                for c in self.files
            },
            "rows": [[r.store, r.module, r.va, r.old, r.new] for r in self.rows],
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

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
            **(
                {
                    "input_digest": self.input_digest,
                    "input_hashes": self.input_hashes,
                    "reference_owners": [
                        {"file": show(p), "owner": f"{s.module}.0x{s.va:08x}"}
                        for p, s in sorted(self.reference_owners.items())
                    ],
                    "preserved_references": [show(p) for p in sorted(self.preserved_references)],
                    "pending_owners": [
                        {"file": show(p), "identity": f"{s.module}.0x{s.va:08x}"}
                        for p, s in sorted(self.pending_owners.items())
                    ],
                }
                if self.input_hashes
                else {}
            ),
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
                if row.get("kind") in {"FUNCTION", "LIBRARY"}:
                    entry = bind_compiled_source(
                        cfg, SourceBinding(module=module, va=va, kind=str(row["kind"])), row
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
            except OSError, UnicodeDecodeError:
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
        self._annotations: dict[Path, list[SourceBinding]] = {}
        self._data_rows: dict[tuple[str, int], dict[str, Any]] | None = None
        self._paths_by_stored: dict[str, Path] | None = None

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

    def annotations(self, path: Path) -> list[SourceBinding]:
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
        if not stored:
            return None
        if self._paths_by_stored is None:
            self._paths_by_stored = {}
            for path in self.paths:
                self._paths_by_stored.setdefault(self.stored_file(path).replace("\\", "/"), path)
        return self._paths_by_stored.get(stored.replace("\\", "/"))

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


def _rename_annotations(cfg: ProjectConfig, path: Path) -> list[SourceBinding]:
    """Read every target's identities, including mixed migrated/inline files."""
    from rebrew.metadata.functions import load_metadata

    metadata_dir = getattr(cfg, "metadata_dir", path.parent)
    parsed = read_source_bindings(
        path, metadata_dir=metadata_dir, project_root=getattr(cfg, "root", None)
    )
    by_identity = {(e.module, e.va, e.kind): e for e in parsed}
    for module in {m for m, _va in load_metadata(metadata_dir, deepcopy=False)}:
        for e in read_source_bindings(
            path,
            target_name=module,
            metadata_dir=metadata_dir,
            project_root=getattr(cfg, "root", None),
        ):
            by_identity[(e.module, e.va, e.kind)] = e
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


def _ordinary_collisions(
    project: _Project, new_name: str, modules: frozenset[str] | None = None
) -> list[tuple[Path, int]]:
    """Sites where *new_name* already names something in the ordinary namespace.

    *modules* limits the check to files that can link with the selected
    definition. A file bound only to other targets is not a duplicate. An
    unscoped file, or a selected definition with no module, keeps the global
    check.
    """
    roles = ORDINARY_ROLES | {ROLE_MACRO_NAME}
    sites: list[tuple[Path, int]] = []
    for path in project.containing(new_name):
        if modules is not None:
            found = project.modules(path)
            if found is not None and not found & modules:
                continue
        sites.extend(
            (path, occ.line)
            for occ in occurrences(project.parsed(path), new_name)
            if occ.role in roles
        )
    return sites


def _row_name_collisions(
    project: _Project,
    new_name: str,
    modules: set[str] | None = None,
    renamed: set[tuple[str, str, int]] | None = None,
) -> list[str]:
    """``MODULE.0xVA`` of every function or data row already named *new_name*.

    With *modules*, only rows of those modules count: each module links its
    own image, so a row of another module with that name is not a duplicate.
    A shared source definition is caught by the source-level check instead.
    Rows in the current plan are the same identities, even when their names
    already agree with the destination and their restored C source does not.
    """
    from rebrew.metadata.functions import load_metadata

    renamed = renamed or set()

    def counted(module: str) -> bool:
        return modules is None or module in modules

    taken = [
        f"{module}.0x{va:08x}"
        for (module, va), row in load_metadata(project.metadata_dir, deepcopy=False).items()
        if counted(module)
        and (KIND_FUNCTION, module, va) not in renamed
        and (
            row.get("name") == new_name
            or (row.get("symbol") and c_name_from_symbol(str(row["symbol"])) == new_name)
        )
    ]
    taken += [
        f"{module}.0x{va:08x}"
        for (module, va), row in project.data_rows().items()
        if counted(module)
        and (KIND_DATA, module, va) not in renamed
        and row.get("name") == new_name
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
    cfg: ProjectConfig,
    symbols: dict[str, dict[str, str]],
    ambiguous_symbols: set[tuple[str, str]] | None = None,
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
            if preset_module_key(module) == preset_module_key(target.module)
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
                target_module_name: str = preset_module_key(target.module),
                path: Path = path,
            ) -> str:
                """Change internal symbols while preserving export names and other options."""
                option, value = match.groups()
                quote = '"' if value.startswith('"') else ""
                body = value[1:-1] if quote else value
                binding, separator, qualifiers = body.partition(",")
                referred = (
                    binding.split("=")
                    if option.upper() == "ALTERNATENAME"
                    else [binding.rsplit("=", 1)[-1]]
                )
                if any(
                    (target_module_name, name) in (ambiguous_symbols or set()) for name in referred
                ):
                    raise RenameError(
                        "ambiguous linker reference to independent same-target definitions; review linker ownership",
                        files=[path],
                    )
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
    from rebrew.metadata.binding_history import historical_source_files
    from rebrew.metadata.bindings import library_bindings_for_file
    from rebrew.metadata.functions import get_entry, load_metadata
    from rebrew.metadata.source_provenance import load_source_files

    if selected.store != KIND_FUNCTION or not is_valid_new_name(old_name):
        raise ValueError("function reference binding requires an unbound C function name")
    context_inputs = _rename_context_inputs(cfg)
    project = _Project(cfg)
    root = getattr(cfg, "root", None) or project.metadata_dir
    retired = set().union(
        *(
            historical_source_files(entry, project.metadata_dir, root)
            for entry in load_metadata(project.metadata_dir, deepcopy=False).values()
        )
    )
    retained = {str(e.get("file") or "") for e in project.data_rows().values()}
    retained.update(e.file for e in load_source_files(project.metadata_dir))
    inactive = {
        path
        for path in project.paths
        if path.suffix.lower() != _HEADER_SUFFIX
        and path.resolve() in retired
        and not project.annotations(path)
        and project.stored_file(path) not in retained
    }
    row = get_entry(project.metadata_dir, selected.va, selected.module)
    new_name = rename_source_name(str(row.get("name") or ""), str(row.get("symbol") or ""))
    destination = project.path_for_stored(str(row.get("file") or ""))
    if destination is None or not is_valid_new_name(new_name):
        raise RenameError("binding destination has no project function definition", files=[])
    defs = {
        p: definitions(project.parsed(p), new_name)
        for p in project.containing(new_name)
        if p not in inactive
    }
    found_defs = [
        (p, d.kind, d.static)
        for p, found in defs.items()
        for d in found
        if not d.definitely_inactive
    ]
    library_identity = (
        row.get("kind") == "LIBRARY"
        and destination.suffix.lower() == ".h"
        and destination.is_file()
        and any(
            e.module == selected.module and e.va == selected.va and e.symbol == row.get("symbol")
            for e in library_bindings_for_file(destination, metadata_dir=project.metadata_dir)
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
    hits = [p for p in project.containing(old_name) if p not in inactive]
    if any(
        rename_source_name(e.name, e.symbol) == old_name
        for path in hits
        for e in [
            *project.annotations(path),
            *library_bindings_for_file(path, metadata_dir=project.metadata_dir),
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
    plan.input_hashes = _rename_source_inputs(project, plan) | context_inputs
    _check_rename_inputs(cfg, plan)
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
    allow_counterpart_name: bool = False,
    rename_file: bool = False,
    new_filename: str | None = None,
    dry_run: bool = False,
    reference_owners: dict[Path, Selection] | None = None,
    preserved_references: set[Path] | None = None,
    pending_owners: dict[Path, Selection] | None = None,
    guarded: bool = False,
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
    if (reference_owners or preserved_references or pending_owners) and (
        store != KIND_FUNCTION or selected is None or definition_file is None or all_modules
    ):
        raise ValueError("reference ownership requires one selected function definition")
    context_inputs = (
        _rename_context_inputs(cfg, include_inventories=bool(pending_owners))
        if reference_owners or preserved_references or pending_owners or guarded
        else {}
    )
    if definition_file is not None and not dry_run:
        read_source_text(definition_file)  # a missing definition is reported as itself
    from rebrew.utils import preset_module_key

    project = _Project(cfg, [definition_file] if definition_file is not None else [])
    kind = KIND_DATA if store == KIND_DATA else KIND_FUNCTION
    plan = RenamePlan(kind=kind, old_name=old_name, new_name=new_name)

    candidates = project.containing(old_name)
    if store == KIND_FUNCTION:
        hits = [
            path
            for path in candidates
            if definitions(project.parsed(path), old_name)
            or function_reference_occurrences(project.parsed(path), old_name)
        ]
    else:
        hits = candidates
    defs = {p: definitions(project.parsed(p), old_name) for p in hits}
    external = {p for p, found in defs.items() if any(not d.static for d in found)}
    statics = {p for p, found in defs.items() if found and all(d.static for d in found)}
    if (
        reference_owners or preserved_references or pending_owners
    ) and definition_file not in external:
        raise RenameError(
            "reference ownership requires an external function definition",
            files=[definition_file] if definition_file else [],
        )

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
        owner_files: dict[Path, Path] = {}
        for reference in preserved_references or set():
            reference = reference.resolve()
            if reference not in hits or reference in external | statics:
                raise RenameError(
                    "preserved reference must select a reference file, not a definition",
                    files=[reference],
                )
            if reference in {p.resolve() for p in reference_owners or {}}:
                raise RenameError(
                    "reference cannot be both preserved and assigned an owner", files=[reference]
                )
            plan.preserved_references.add(reference)
        for reference, owner in (reference_owners or {}).items():
            from rebrew.metadata.functions import get_entry

            reference = reference.resolve()
            if reference in plan.reference_owners:
                raise ValueError(f"duplicate reference-owner selection: {reference}")
            if reference not in hits or reference in external | statics:
                raise RenameError(
                    "reference owner must select a reference file, not a definition",
                    files=[reference],
                )
            owner_row = get_entry(project.metadata_dir, owner.va, owner.module)
            owner_file = project.path_for_stored(str(owner_row.get("file") or ""))
            if (
                owner.store != KIND_FUNCTION
                or owner_file not in external
                or rename_source_name(
                    str(owner_row.get("name") or ""), str(owner_row.get("symbol") or "")
                )
                != old_name
            ):
                raise RenameError(
                    "reference owner is not a definition of the selected name", files=[reference]
                )
            assert owner_file is not None
            owner_files[reference] = owner_file
            plan.reference_owners[reference] = owner
        for reference, pending in (pending_owners or {}).items():
            reference = reference.resolve()
            if reference not in owner_files or owner_files[reference] not in chosen:
                raise RenameError(
                    "pending owner requires a selected reference owner", files=[reference]
                )
            if reference in plan.pending_owners or reference in plan.preserved_references:
                raise RenameError("duplicate or preserved pending owner", files=[reference])
            _validate_pending_owner(cfg, project, reference, owner_files[reference], pending)
            plan.pending_owners[reference] = pending
        rename_set |= _attributed_references(
            project,
            hits,
            chosen,
            external - chosen,
            statics | plan.preserved_references,
            owner_files,
            old_name,
            plan.pending_owners,
        )

    for path in sorted(rename_set, key=str):
        parsed = project.parsed(path)
        if store == KIND_FUNCTION:
            refs = function_reference_occurrences(parsed, old_name)
            if comments:
                refs.extend(
                    occurrence
                    for occurrence in occurrences(parsed, old_name)
                    if occurrence.role == ROLE_COMMENT
                )
            spans = [(o.start, o.end, o.line, o.column, o.role) for o in refs]
        else:
            roles = ORDINARY_ROLES | ({ROLE_COMMENT} if comments else set())
            spans = [
                (o.start, o.end, o.line, o.column, o.role)
                for o in occurrences(parsed, old_name)
                if o.role in roles
            ]
        change = _file_change(project, path, spans, new_name)
        if change is not None:
            plan.files.append(change)

    _plan_symbol_rows(project, plan, chosen, rename_set, selected, store)
    _check_acknowledged(plan, selected, all_modules=all_modules, require_ack=require_ack)

    collision_modules: frozenset[str] | None = None
    if store == KIND_FUNCTION and chosen:
        visible: set[str] = set()
        for path in chosen:
            found = project.modules(path)
            if found is None:
                visible.clear()
                break
            visible |= found
        else:
            collision_modules = frozenset(visible)
    collisions = _ordinary_collisions(project, new_name, collision_modules)
    if collisions and allow_counterpart_name:
        # One source tree carries each target's counterpart body in the same
        # file behind that target's define, and shared headers declare the name
        # for every caller. --shared-definition is the caller's reviewed
        # acknowledgement of exactly that, so only a row of the selected
        # definition's own module can still make the name a duplicate symbol;
        # _row_name_collisions below enforces that.
        collisions = []
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
    taken = _row_name_collisions(
        project,
        new_name,
        renamed_modules or None,
        {(row.store, row.module, row.va) for row in plan.rows},
    )
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
    ambiguous_symbols: set[tuple[str, str]] = set()
    if reference_owners or preserved_references or pending_owners:
        from rebrew.utils import preset_module_key

        for other in external - chosen:
            for ann in project.annotations(other):
                native = ann.symbol or "_" + ann.name
                if rename_source_name(ann.name, ann.symbol) == old_name:
                    ambiguous_symbols.add((preset_module_key(ann.module), native))
    plan.files.extend(_linker_reference_changes(cfg, symbols, ambiguous_symbols))
    if reference_owners or preserved_references or pending_owners or guarded:
        if reference_owners:
            plan.notes.append(
                "Explicit reference ownership is a reviewed source claim, not native call proof; reverify every affected target."
            )
        if plan.preserved_references:
            plan.notes.append(
                "Preserved references remain unchanged; verify their linked providers after renaming."
            )
        if plan.pending_owners:
            plan.notes.append(
                "Pending owners are prospective, not native or provider proof; rebind and verify each pending identity before linking."
            )
        plan.input_hashes = _rename_source_inputs(project, plan) | context_inputs
        _check_rename_inputs(cfg, plan)
    return plan


def _attributed_references(
    project: _Project,
    hits: list[Path],
    chosen: set[Path],
    others: set[Path],
    statics: set[Path],
    owners: dict[Path, Path] | None = None,
    old_name: str | None = None,
    pending: dict[Path, Selection] | None = None,
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
        if path in (owners or {}):
            from rebrew.utils import preset_module_key

            owner = (owners or {})[path]
            owner_mods = frozenset(
                preset_module_key(a.module)
                for a in project.annotations(owner)
                if a.kind in {"FUNCTION", "STUB", "LIBRARY"}
                and rename_source_name(a.name, a.symbol) == old_name
            )
            pending_owner = (pending or {}).get(path)
            pending_mods = (
                frozenset([preset_module_key(pending_owner.module)])
                if pending_owner
                else frozenset()
            )
            if mods is not None and not mods <= owner_mods | pending_mods:
                raise RenameError("reference owner is unavailable in a caller target", files=[path])
            if owner in chosen:
                selected.add(path)
            continue
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


def _validate_pending_owner(
    cfg: ProjectConfig, project: _Project, path: Path, owner: Path, pending: Selection
) -> None:
    from rebrew.catalog.loaders import load_function_structure
    from rebrew.config import inventory_path_for, load_config, target_module
    from rebrew.metadata.functions import get_entry
    from rebrew.utils import preset_module_key

    module = preset_module_key(pending.module)
    mods = project.modules(path)
    owner_mods = {preset_module_key(a.module) for a in project.annotations(owner)}
    targets = [load_config(_root(cfg), target=name) for name in getattr(cfg, "all_targets", [])]
    matches = [t for t in targets if preset_module_key(target_module(t) or "") == module]
    row = get_entry(project.metadata_dir, pending.va, pending.module)
    history = row.get("binding_history", []) if row else []
    if (
        pending.store != KIND_FUNCTION
        or mods is None
        or module not in mods
        or module in owner_mods
        or len(matches) != 1
        or not row
        or row.get("file")
        or not history
        or history[-1].get("action") != "retire"
    ):
        raise RenameError(
            "pending owner must be a retired unbound identity in a caller target", files=[path]
        )
    target = matches[0]
    inventory = inventory_path_for(target.reversed_dir, target)
    if sum(entry.va == pending.va for entry in load_function_structure(inventory)) != 1:
        raise RenameError("pending owner must be unique in the target inventory", files=[path])


def _rename_context_inputs(
    cfg: ProjectConfig, *, include_inventories: bool = False
) -> dict[str, str]:
    from rebrew.config import inventory_path_for, load_config

    metadata = Path(getattr(cfg, "metadata_dir", None) or cfg.reversed_dir)
    paths = set(metadata_store_paths(metadata))
    root = _root(cfg)
    if root is not None and (root / "rebrew-project.toml").exists():
        paths.add(root / "rebrew-project.toml")
    if root is not None:
        paths.update((root / "layout").rglob("*.rsp"))
    targets = [load_config(root, target=name) for name in getattr(cfg, "all_targets", [])] or [cfg]
    for target in targets:
        binary = getattr(target, "target_binary", None)
        if binary is not None:
            paths.add(Path(binary))
        if include_inventories:
            paths.add(inventory_path_for(target.reversed_dir, target))
    return {str(p.resolve()): input_digest(p) for p in paths}


def _rename_source_inputs(project: _Project, plan: RenamePlan) -> dict[str, str]:
    inputs = {
        str(p.resolve()): hashlib.sha256(text.encode(encoding)).hexdigest()
        for p, (text, encoding, _raw) in project.texts.items()
    }
    inputs.update(
        {
            str(c.path.resolve()): hashlib.sha256(c.old_text.encode(c.encoding)).hexdigest()
            for c in plan.files
        }
    )
    return inputs


def _check_rename_inputs(cfg: ProjectConfig, plan: RenamePlan) -> None:
    try:
        project = _Project(cfg, [c.path for c in plan.files])
        current = _rename_source_inputs(project, plan) | _rename_context_inputs(
            cfg, include_inventories=bool(plan.pending_owners)
        )
        # FileChange.old_text belongs to the old plan; compare those paths to disk too.
        current.update(
            {
                str(c.path.resolve()): hashlib.sha256(c.path.read_bytes()).hexdigest()
                for c in plan.files
            }
        )
    except (OSError, ValueError, RenameError) as exc:
        raise RenameError(f"rename inputs changed; review a new preview ({exc})", files=[]) from exc
    if current != plan.input_hashes:
        raise RenameError("rename inputs changed; review a new preview", files=[])


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
            if entry.kind not in FUNCTION_KINDS:
                continue
            if entry.name != old and c_name_from_symbol(entry.symbol or "") != old:
                # A metadata rename can precede the C edit. The sole definition
                # in its owning file identifies the row without a comment hint.
                source_defs = definitions(project.parsed(path), old)
                canonical_is_new = (
                    entry.name == new or c_name_from_symbol(entry.symbol or "") == new
                )
                from rebrew.c_parser import find_c_function_definitions

                names = find_c_function_definitions(project.texts[path][0])
                if not (
                    canonical_is_new and source_defs and len(names) == 1 and names[0][0] == old
                ):
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


def is_decorated_symbol(name: str) -> bool:
    """An MSVC linker identifier rather than a C source identifier."""
    return re.fullmatch(r"[$?A-Za-z_][$?A-Za-z0-9_@]*", name) is not None and not is_valid_new_name(
        name
    )


def plan_header_row_rename(
    cfg: ProjectConfig, module: str, va: int, new_name: str
) -> RenamePlan | None:
    """Rename a metadata-only library identity; inventory comments are never state."""
    from rebrew.metadata.functions import load_metadata

    rows = load_metadata(cfg.metadata_dir)
    stored = rows.get((module, va))
    if not stored or stored.get("kind") != "LIBRARY":
        return None
    if stored.get("file") and Path(str(stored["file"])).suffix.lower() != ".h":
        return None
    if not (is_valid_new_name(new_name) or is_decorated_symbol(new_name)):
        raise ValueError(f"invalid C or linker identifier {new_name!r}")
    old_symbol = str(stored.get("symbol") or "")
    symbol = new_name if is_decorated_symbol(new_name) else redecorated_symbol(old_symbol, new_name)
    collisions = [
        f"{m}.0x{v:08x}"
        for (m, v), row in rows.items()
        if m == module and v != va and (row.get("name") == new_name or row.get("symbol") == symbol)
    ]
    if collisions:
        raise RenameError(f"cannot create duplicate symbol {new_name}: {collisions}", files=[])
    plan = RenamePlan(kind=KIND_FUNCTION, old_name=str(stored.get("name") or ""), new_name=new_name)
    plan.rows.append(
        RowChange(
            "function",
            module,
            va,
            {"name": str(stored.get("name") or ""), "symbol": old_symbol},
            {"name": new_name, "symbol": symbol},
        )
    )
    return plan


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
        multi = len(read_source_bindings(filepath, metadata_dir=metadata_dir)) > 1
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
    if plan.input_hashes:
        _check_rename_inputs(cfg, plan)
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
            except OSError, UnicodeEncodeError:
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
        from rebrew.metadata.functions import record_function_rows

        record_function_rows(metadata_dir, function_rows, overwrite_name=True, updated_by="rename")
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
            f"cannot rename {filepath}: old name is empty (missing FUNCTION binding or symbol)"
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
