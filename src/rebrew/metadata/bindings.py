"""Join address-only source locations with authoritative function and data stores."""

from __future__ import annotations

import bisect
import copy
import logging
import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, ClassVar, Final

from rebrew.c_parser import extract_function_name_from_line
from rebrew.metadata.anchors import metadata_comments, parse_address_anchors
from rebrew.utils import preset_module_key, read_source_text, rel_display_path
from rebrew.workspace.status import MATCHED_STATUSES

logger = logging.getLogger(__name__)
MIN_VALID_VA = 0x1000
SYMBOL_KINDS = {"FUNCTION", "LIBRARY", "STUB", "GLOBAL", "DATA", "VTABLE", "STRING"}
FUNCTION_KINDS = frozenset({"FUNCTION", "LIBRARY", "STUB"})
DATA_KINDS = frozenset({"GLOBAL", "DATA", "VTABLE", "STRING"})
_STDCALL_RE = re.compile(r"\b(?:__stdcall|WINAPI|CALLBACK|APIENTRY)\b")
_FASTCALL_RE = re.compile(r"\b__fastcall\b")
_VECTORCALL_RE = re.compile(r"\b__vectorcall\b")
_CFLAGS_GLUED_RE = re.compile(r"^/\w+/\w+")
_TEMPLATE_STRIP_RE = re.compile(r"<[^<>]*>")
_DECLSPEC_STRIP_RE = re.compile(r"__declspec\s*\([^)]*\)")


def min_valid_va_for(cfg: Any) -> int:
    """The lowest legitimate function VA for a target's architecture.

    16-bit DOS targets (MZ/NE, ``x86_16``) address code from segment 0 —
    VAs legitimately start at 0 (the MZ code region base), so the 0x1000
    PE-era floor does not apply.  Returns ``0`` for ``x86_16`` targets,
    ``MIN_VALID_VA`` otherwise.
    """
    if getattr(cfg, "arch", "") == "x86_16":
        return 0
    return MIN_VALID_VA


def kind_for_module(module: str, status: str, library_modules: set[str] | None = None) -> str:
    """Derive expected marker type from module name and status.

    Args:
        module: Module identifier from the marker line (e.g. "SERVER", "MSVCRT").
        status: Status string (e.g. "EXACT", "STUB").
        library_modules: Set of module names that should use LIBRARY marker.
                         Defaults to empty set if not provided.

    Returns:
        ``"STUB"`` if status is STUB, ``"LIBRARY"`` if module is in
        *library_modules*, otherwise ``"FUNCTION"``.
    """
    if status == "STUB":
        return "STUB"
    if library_modules and module in library_modules:
        return "LIBRARY"
    return "FUNCTION"


def has_skip_annotation(
    filepath: Path,
    metadata_dir: Path | None = None,
    *,
    annotations: list[SourceBinding] | None = None,
) -> bool:
    """Return True if a function in *filepath* is marked as skippable.

    Checks ``rebrew-functions.toml`` metadata for a truthy ``skip`` field **or**
    ``status = "SKIP"`` on THIS file's own (module, va) entries only — a skip
    anywhere else in the project must not empty ``match --all``'s stub
    collection.  Both parking signals mean the same thing; matching only the
    ``skip`` field left ``status=SKIP`` entries in the GA/match batch.
    Returns ``False`` immediately when *metadata_dir* is ``None``.

    Pass *annotations* when the caller already parsed the file (with or
    without metadata overlay) to avoid a second structural parse.
    """
    if metadata_dir is None:
        return False
    from rebrew.metadata.functions import canonical_status, load_metadata

    entries = load_metadata(metadata_dir, deepcopy=False)
    anns = (
        annotations
        if annotations is not None
        else read_source_bindings(filepath, metadata_dir=metadata_dir)
    )
    for ann in anns:
        entry = entries.get((ann.module, ann.va), {})
        raw_skip = entry.get("skip", "")
        if raw_skip and str(raw_skip).strip().lower() not in ("", "0", "false", "no"):
            return True
        raw_status = entry.get("status", "")
        if raw_status and canonical_status(str(raw_status)) == "SKIP":
            return True
        # Metadata-overlaid parses already put STATUS on the SourceBinding.
        if canonical_status(getattr(ann, "status", "") or "") == "SKIP":
            return True
    return False


def resolve_symbol(entry: SourceBinding, filepath: Path) -> str:
    """Resolve a usable symbol name from an annotation, falling back to filename."""
    if entry.is_data:
        return entry.name
    symbol = entry.symbol
    if symbol and symbol != "?":
        return symbol
    if entry.name and entry.name != "?":
        return derive_c_symbol(entry.name, entry.prototype)
    return "_" + filepath.stem


_FIELD_ALIASES: Final[dict[str, str]] = {"globals": "globals_list"}

# Exact types SourceBinding.__deepcopy__ shares instead of copying: immutable
# scalars only (exact type match — a subclass or a tuple that could hold
# mutables never takes this path).
_COPY_SCALAR_TYPES: tuple[type, ...] = (
    str,
    bytes,
    int,
    float,
    complex,
    bool,
    type(None),
    frozenset,
)

#: Exact container types an empty value can be rebuilt from directly.  Only
#: these: a non-empty container, or one whose type may hold mutables, still
#: goes through ``copy.deepcopy``.
_EMPTY_CONTAINER_TYPES: tuple[type, ...] = (list, dict)


@dataclass
class SourceBinding:
    """Parsed function annotation from a decomp .c file.

    Supports dict-like access (``ann["va"]``, ``ann["status"] = "EXACT"``)
    for interoperability with generic dict-processing code.
    """

    va: int = 0
    size: int = 0
    name: str = ""
    symbol: str = ""
    module: str = ""
    status: str = ""
    cflags: str = ""
    toolchain: str = ""  # per-function toolchain override (e.g. "msvc-5.0")
    kind: str = ""
    filepath: str = ""
    source: str = ""
    blocker: str = ""
    blocker_delta: int | None = None
    note: str = ""
    ghidra: str = ""
    # Parking signal from rebrew-functions.toml; distinct from status=SKIP
    # (a STUB entry can still be parked).
    skip: str = ""
    prototype: str = ""
    struct: str = ""
    callers: str = ""
    globals_list: list[str] = field(default_factory=list)
    locals: dict[str, Any] = field(default_factory=dict)
    comments: dict[str, Any] = field(default_factory=dict)
    section: str = ""  # .data, .rdata, .bss — used by DATA annotations
    line: int = 0  # 1-based line number of the marker in the source file
    prove_constraints: dict[str, Any] = field(default_factory=dict)
    updated_by: str = ""
    updated_at: str = ""
    origins: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    comparison_inputs: dict[str, str] | None = field(default=None, repr=False)

    # -- Dict-like access and field aliases --

    def __getitem__(self, key: str) -> Any:
        """Return the field value for *key* (supports field aliases)."""
        attr = _FIELD_ALIASES.get(key, key)
        try:
            return getattr(self, attr)
        except AttributeError:
            raise KeyError(key) from None

    def __setitem__(self, key: str, value: Any) -> None:
        """Set the field *key* to *value* (supports field aliases)."""
        attr = _FIELD_ALIASES.get(key, key)
        if hasattr(self, attr):
            object.__setattr__(self, attr, value)
        else:
            raise KeyError(key)

    # Class-level cache for field names — computed once, not per __contains__ call.
    _field_names: ClassVar[frozenset[str] | None] = None

    def __contains__(self, key: str) -> bool:
        """Return True if *key* (or its alias) is a field of this SourceBinding."""
        attr = _FIELD_ALIASES.get(key, key)
        if SourceBinding._field_names is None:
            SourceBinding._field_names = frozenset(f.name for f in fields(self))
        return attr in SourceBinding._field_names

    def get(self, key: str, default: Any = None) -> Any:
        """Return the value for *key*, or *default* if not present."""
        try:
            return self[key]
        except KeyError:
            return default

    def __deepcopy__(self, memo: dict[int, Any]) -> SourceBinding:
        """Copy with full isolation at less than half the generic cost.

        ``copy.deepcopy``'s default dataclass path walks every field
        through ``_reconstruct``/dispatch (~7-8 µs per annotation — the
        dominant per-entry cost of ``_finalize_entries`` on every
        source scan).  Exact-typed immutable fields are shared; every
        other value (the list/dict fields and anything nested inside
        them) still goes through ``copy.deepcopy``, so mutating a copy's
        ``locals``/``comments`` can never reach the memoized original.

        An empty ``list``/``dict`` field — the common case for a plain
        FUNCTION marker — takes ``type(value)()`` instead: that is what
        ``copy.deepcopy`` returns for an empty container (a fresh, equal,
        independent one), without the dispatch, ``_keep_alive`` and ``memo``
        bookkeeping.  The fields land as one ``__dict__`` assignment rather
        than one ``object.__setattr__`` per field; measured at ~40% off the
        empty-annotation copy and ~25% off a filled one, on the per-entry
        cost of every whole-tree source scan.
        """
        cls = type(self)
        twin = cls.__new__(cls)
        memo[id(self)] = twin
        fields_copy: dict[str, Any] = {}
        for name, value in self.__dict__.items():
            if type(value) in _COPY_SCALAR_TYPES:
                fields_copy[name] = value
            elif not value and type(value) in _EMPTY_CONTAINER_TYPES:
                fields_copy[name] = type(value)()
            else:
                fields_copy[name] = copy.deepcopy(value, memo)
        twin.__dict__ = fields_copy
        return twin

    @property
    def is_data(self) -> bool:
        """True for data annotations (GLOBAL/DATA/VTABLE/STRING markers) — never compiled."""
        return self.kind in DATA_KINDS

    @property
    def is_function(self) -> bool:
        """True for compilable code annotations (FUNCTION/LIBRARY/STUB).

        An empty ``kind`` also counts, so a caller scanning raw records
        can read this before the marker has been resolved.
        """
        if not self.kind:
            return True
        return self.kind in FUNCTION_KINDS

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output and generic dict processing."""
        d = {
            "va": self.va,
            "size": self.size,
            "name": self.name,
            "symbol": self.symbol,
            "module": self.module,
            "status": self.status,
            "cflags": self.cflags,
            "toolchain": self.toolchain,
            "kind": self.kind,
            "filepath": self.filepath,
            "source": self.source,
            "blocker": self.blocker,
            "blocker_delta": self.blocker_delta,
            "note": self.note,
            "ghidra": self.ghidra,
            "prototype": self.prototype,
            "struct": self.struct,
            "callers": self.callers,
            "globals": self.globals_list,
            "line": self.line,
        }
        if self.section:
            d["section"] = self.section
        if self.prove_constraints:
            d["prove_constraints"] = self.prove_constraints
        if self.locals:
            d["locals"] = self.locals
        if self.comments:
            d["comments"] = self.comments
        # Derived predicates ride along so dict-shaped annotations answer
        # the same "compilable?" question without re-spelling the sets.
        d["is_data"] = self.is_data
        d["is_function"] = self.is_function
        return d

    def validate(
        self,
        library_modules: set[str] | None = None,
        min_va: int = MIN_VALID_VA,
    ) -> tuple[list[str], list[str]]:
        """Validate annotation fields. Returns (errors, warnings)."""
        errors: list[str] = []
        warnings: list[str] = []

        if self.kind and self.kind not in SYMBOL_KINDS:
            errors.append(f"Invalid marker type: {self.kind}")

        if self.va < min_va:
            errors.append(f"VA 0x{self.va:x} is suspicious (below 0x{min_va:x})")

        # Only code annotations carry a byte size.  A data marker
        # (GLOBAL/DATA/VTABLE/STRING, see DATA_KINDS) describes a global whose
        # extent lives in rebrew-data.toml, so demanding size > 0 here rejected
        # files that `rebrew lint` accepts: one data marker in an
        # otherwise-valid source made `rebrew diff --fix-blocker` abort with
        # "Invalid SIZE: 0" and refuse to refresh that function's blocker.
        if not self.is_data and self.size <= 0:
            errors.append(f"Invalid SIZE: {self.size}")

        # Validate CFLAGS format if present (not required — falls back to target default)
        if self.cflags.strip():
            flags = self.cflags.strip().split()
            warnings.extend(
                f"CFLAGS token '{flag}' doesn't start with '/' or '-' "
                "(expected MSVC-style flags like /O2 /Gd)"
                for flag in flags
                if not flag.startswith("/") and not flag.startswith("-")
            )
            # Detect common typo: flags glued together like "/O2/Gd"
            warnings.extend(
                f"CFLAGS token '{flag}' looks like multiple flags glued together (missing space?)"
                for flag in flags
                if _CFLAGS_GLUED_RE.match(flag)
            )

        # Check marker consistency against module name.  A STUB-status function
        # may keep either its STUB or FUNCTION marker (status lives in
        # rebrew-functions.toml). LIBRARY may use the binary's target module:
        # vendored source is still target-scoped, even when attributed to a library.
        _lib = library_modules or set()
        if self.module in _lib or self.kind == "LIBRARY":
            expected_marker = "LIBRARY"
            marker_ok = self.kind == "LIBRARY"
        elif self.status == "STUB":
            expected_marker = "FUNCTION"
            marker_ok = self.kind in ("FUNCTION", "STUB")
        else:
            expected_marker = "FUNCTION"
            marker_ok = self.kind == "FUNCTION"
        if self.kind and not marker_ok:
            warnings.append(
                f"Marker {self.kind} inconsistent with module {self.module!r} "
                f"(expected {expected_marker})"
            )

        if self.status == "STUB" and not self.blocker:
            warnings.append("STUB function missing BLOCKER annotation")

        if self.module in _lib and not self.source:
            warnings.append(
                f"Library module {self.module!r} missing SOURCE annotation "
                "(reference file, e.g. SBHEAP.C:195 or deflate.c)"
            )

        if self.status == "NEAR_MATCHING" and self.kind == "STUB":
            warnings.append(f"Contradictory: status is {self.status} but marker is STUB")

        return errors, warnings


def make_function_binding(
    va: int,
    size: int,
    name: str,
    symbol: str,
    status: str,
    cflags: str,
    kind: str,
    filepath: str,
    module: str = "",
    source: str = "",
    blocker: str = "",
    note: str = "",
    globals_list: list[str] | None = None,
    toolchain: str = "",
) -> SourceBinding:
    """Create an SourceBinding instance."""
    return SourceBinding(
        va=va,
        size=size,
        name=name,
        symbol=symbol,
        module=module,
        status=status,
        cflags=cflags,
        toolchain=toolchain,
        kind=kind,
        filepath=filepath,
        source=source,
        blocker=blocker,
        note=note,
        globals_list=globals_list or [],
    )


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


_STDCALL_TYPE_SIZES: dict[str, int] = {
    "double": 8,
    "__int64": 8,
    "long long": 8,
    "unsigned long long": 8,
    "LONGLONG": 8,
    "ULONGLONG": 8,
}
_STDCALL_DEFAULT_SIZE = 4  # int, char, short, pointers, etc. all push 4 bytes
_STDCALL_SIZED_TYPE_RE = re.compile(
    r"\b(?:"
    + "|".join(re.escape(t) for t in sorted(_STDCALL_TYPE_SIZES, key=len, reverse=True))
    + r")\b"
)


def _calc_stdcall_param_size(proto: str) -> int | None:
    """Calculate the total parameter stack size for a __stdcall prototype.

    Parses the parameter list from a C prototype string and sums the stack
    sizes of each parameter.  Returns None if the prototype cannot be parsed
    (e.g. variadic ``...`` or missing parens).

    Examples::

        >>> _calc_stdcall_param_size("int __stdcall handler(int a, int b, int c)")
        12
        >>> _calc_stdcall_param_size("int WINAPI func(EXCEPTION_POINTERS* p)")
        4
        >>> _calc_stdcall_param_size("void __stdcall noargs(void)")
        0
    """
    # Extract the parameter list between parens.  ``__declspec(...)`` groups
    # contain parens of their own (``__declspec(naked)``), so a naive
    # ``find("(")`` grabs the declspec group and counts its content as a
    # parameter — a ``void __declspec(naked) __stdcall foo(void)`` would
    # decorate ``_foo@4`` instead of ``_foo@0``.  Strip declspec groups first.
    cleaned = _DECLSPEC_STRIP_RE.sub("", proto)
    paren_start = cleaned.find("(")
    paren_end = cleaned.rfind(")")
    if paren_start < 0 or paren_end < 0 or paren_end <= paren_start:
        return None

    params_str = cleaned[paren_start + 1 : paren_end].strip()

    # No parameters or void
    if not params_str or params_str == "void":
        return 0

    # Variadic functions can't be __stdcall-decorated
    if "..." in params_str:
        return None

    # Strip template parameter lists before splitting on commas.
    # Without this, a parameter like ``std::pair<int,int>`` would be
    # counted as two parameters, doubling the computed stack size and
    # producing an incorrect decorated name like ``_foo@12`` instead of
    # ``_foo@4``.  Template args never appear at the top-level comma
    # boundary — only as nested angle-bracket content.
    #
    # Iterative stripping handles arbitrary nesting depth:
    # e.g. std::map<int, std::pair<A, B>> requires two passes:
    #   pass 1: removes "<A, B>" → std::map<int, std::pair>
    #   pass 2: removes "<int, std::pair>" → (empty)
    prev = None
    while prev != params_str:
        prev = params_str
        params_str = _TEMPLATE_STRIP_RE.sub("", params_str)

    # Split on top-level commas only: a function-pointer parameter
    # ``int (*cb)(int, int)`` is one parameter.
    params: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(params_str):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            params.append(params_str[start:i])
            start = i + 1
    params.append(params_str[start:])

    total = 0
    for param in params:
        param = param.strip()
        if not param:
            continue
        matched_size = _STDCALL_DEFAULT_SIZE
        # Pointers, references, arrays (decay to pointers), and function
        # pointers push 4 bytes whatever they point to.
        if not any(c in param for c in "*&[("):
            sized = _STDCALL_SIZED_TYPE_RE.search(param)
            if sized:
                matched_size = _STDCALL_TYPE_SIZES[sized.group(0)]
        total += matched_size

    return total


def _convention_head(proto: str) -> str:
    """Return the text before the parameter list, without ``__declspec``.

    A convention inside a parameter (``void (__vectorcall *cb)(int)``) is
    not the function's own convention.
    """
    cleaned = _DECLSPEC_STRIP_RE.sub("", proto)
    paren = cleaned.find("(")
    return cleaned if paren < 0 else cleaned[:paren]


def derive_c_symbol(name: str, c_func_proto: str) -> str:
    """MSVC symbol decoration for *name* from its prototype.

    ``"_" + name`` for __cdecl (default), ``"_" + name + "@N"`` for
    __stdcall/WINAPI, ``"@" + name + "@N"`` for __fastcall (ecx/edx args
    are still counted in the decoration's N on MSVC), ``name + "@@N"`` for
    __vectorcall (the whole parameter list, including register arguments).
    """
    symbol = "_" + name if name else ""
    # Only the convention before the parameter list. A ``__fastcall`` on a
    # parameter used to decorate a stdcall function as ``@name@N``.
    head = _convention_head(c_func_proto) if c_func_proto else ""
    if name and head and _VECTORCALL_RE.search(head):
        param_size = _calc_stdcall_param_size(c_func_proto)
        if param_size is not None:
            symbol = f"{name}@@{param_size}"
    elif name and head and _FASTCALL_RE.search(head):
        param_size = _calc_stdcall_param_size(c_func_proto)
        if param_size is not None:
            symbol = f"@{name}@{param_size}"
    elif name and head and _STDCALL_RE.search(head):
        # Calculate parameter stack size from prototype for decorated name
        param_size = _calc_stdcall_param_size(c_func_proto)
        if param_size is not None:
            symbol = f"_{name}@{param_size}"
    return symbol


_METADATA_FILE_INDEX: dict[int, dict[str, list[tuple[str, int, dict[str, Any]]]]] = {}
_METADATA_FILE_INDEX_MAX = 4

#: Pins each indexed document so a freed entry's ``id`` is never reused as a
#: live cache key.
_METADATA_FILE_INDEX_OWNER: dict[int, dict[tuple[str, int], dict[str, Any]]] = {}
#: The owner hit, the two eviction clears, and the two stores are one
#: check-then-act over two parallel dicts; ``rebrew match batch --jobs N`` reaches
#: this from pool threads.  Held only for the dict work — the index build below
#: walks the whole entry table and stays outside.
_METADATA_FILE_INDEX_LOCK = threading.Lock()


def _metadata_file_index(
    entries_by_key: dict[tuple[str, int], dict[str, Any]],
) -> dict[str, list[tuple[str, int, dict[str, Any]]]]:
    """Index *entries_by_key* by its normalized ``file`` field.

    Keyed on the identity of the cached document, so a metadata reload
    invalidates the index and a fresh caller that mutated a deepcopy builds
    its own.
    """
    key = id(entries_by_key)
    with _METADATA_FILE_INDEX_LOCK:
        if _METADATA_FILE_INDEX_OWNER.get(key) is entries_by_key:
            cached = _METADATA_FILE_INDEX.get(key)
            if cached is not None:
                return cached
    index: dict[str, list[tuple[str, int, dict[str, Any]]]] = {}
    for (module, va), entry in entries_by_key.items():
        stored = str(entry.get("file", "")).replace("\\", "/")
        if stored:
            index.setdefault(stored, []).append((module, va, entry))
    with _METADATA_FILE_INDEX_LOCK:
        if len(_METADATA_FILE_INDEX) >= _METADATA_FILE_INDEX_MAX:
            _METADATA_FILE_INDEX.clear()
            _METADATA_FILE_INDEX_OWNER.clear()
        _METADATA_FILE_INDEX[key] = index
        _METADATA_FILE_INDEX_OWNER[key] = entries_by_key
    return index


def _path_suffixes(rel_path: str) -> list[str]:
    """Every distinct path suffix of *rel_path* that an entry may store.

    ``"a/b/c.c"`` yields ``["a/b/c.c", "b/c.c", "c.c"]`` — the full relative
    path plus each component-aligned suffix, which covers the bare filename.
    """
    parts = rel_path.split("/")
    return ["/".join(parts[i:]) for i in range(len(parts))]


def function_rows_for_file(
    filepath: Path,
    metadata_dir: Path,
    function_entries: dict[tuple[str, int], dict[str, Any]],
) -> list[tuple[str, int, dict[str, Any]]]:
    """Function-store rows whose ``file`` names *filepath*.

    A pure-C file has no marker blocks, so its blockers and statuses live only
    in these rows.
    """
    rel = os.path.relpath(filepath, metadata_dir).replace(os.sep, "/")
    index = _metadata_file_index(function_entries)
    seen: dict[tuple[str, int], tuple[str, int, dict[str, Any]]] = {}
    for suffix in _path_suffixes(rel):
        for row in index.get(suffix, []):
            seen[(row[0], row[1])] = row
    return list(seen.values())


def file_backed_by_metadata(
    filepath: Path,
    metadata_dir: Path,
    *,
    project_root: Path | None = None,
    function_entries: dict[tuple[str, int], dict[str, Any]] | None = None,
    data_entries: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> bool:
    """True when a store row's ``file`` matches *filepath*.

    A pure-C source has no marker line. Lint treats it as annotated when
    either store already names it, and ignores it when neither does.
    *function_entries* and *data_entries* are the caller's already-loaded
    maps; omitted maps are read from *metadata_dir*. Explicit LIBRARY source
    bindings use exact paths relative to *project_root*, when supplied.
    """
    rel = os.path.relpath(filepath, metadata_dir).replace(os.sep, "/")
    suffixes = set(_path_suffixes(rel))
    if function_entries is None:
        from rebrew.metadata.functions import load_metadata

        function_entries = load_metadata(metadata_dir, deepcopy=False)
    index = _metadata_file_index(function_entries)
    if project_root is not None:
        try:
            project_rel = filepath.resolve().relative_to(project_root.resolve()).as_posix()
        except ValueError:
            project_rel = ""
        if project_rel and any(
            entry.get("kind") == "LIBRARY" for _module, _va, entry in index.get(project_rel, [])
        ):
            return True
    if any(candidate in index for candidate in suffixes):
        return True
    if data_entries is None:
        from rebrew.metadata.data import data_rows_for_path

        return bool(data_rows_for_path(metadata_dir, filepath))
    for entry in data_entries.values():
        stored = str(entry.get("file", "")).replace("\\", "/")
        if stored and stored in suffixes:
            return True
    return False


def _annotations_from_metadata(
    filepath: Path,
    target_name: str | None,
    base_dir: Path | None,
    metadata_dir: Path | None,
) -> list[SourceBinding]:
    """Build source bindings from canonical rows for this file.

    Function and data stores own identity and state. Optional address anchors
    provide declaration locations. Invalid stores raise instead of omitting rows.
    """
    if metadata_dir is None:
        return []
    results = _function_annotations_from_metadata(filepath, target_name, base_dir, metadata_dir)
    results.extend(_data_annotations_from_metadata(filepath, target_name, base_dir, metadata_dir))
    results.sort(key=lambda ann: ann.va)
    return results


def _function_annotations_from_metadata(
    filepath: Path,
    target_name: str | None,
    base_dir: Path | None,
    metadata_dir: Path,
) -> list[SourceBinding]:
    """Function rows from ``rebrew-functions.toml`` whose ``file`` matches."""
    from rebrew.metadata.functions import apply_metadata_entry, load_metadata

    entries_by_key = load_metadata(metadata_dir, deepcopy=False)
    if not entries_by_key:
        return []

    rel_md = os.path.relpath(filepath, metadata_dir).replace(os.sep, "/")
    matches: list[tuple[str, int, dict[str, Any]]] = []
    # The stored `file` matches the exact relative path, the bare filename,
    # or any trailing path suffix of it (projects that moved the metadata
    # root).  A source tree scan runs this once per marker-less file, so
    # resolve the match through an index over the stored paths instead of
    # re-scanning every entry per file.
    index = _metadata_file_index(entries_by_key)
    for candidate in _path_suffixes(rel_md):
        for module, va, entry in index.get(candidate, ()):
            matches.append((module, va, entry))

    rel = rel_display_path(filepath, base_dir)
    results: list[SourceBinding] = []
    prototypes: _DefinitionPrototypes | None = None
    for module, va, entry in matches:
        if target_name and module and preset_module_key(module) != preset_module_key(target_name):
            continue
        ann = SourceBinding(
            va=va,
            module=module,
            kind=str(entry.get("kind", "FUNCTION")),
            symbol=str(entry.get("symbol", "")),
            name=str(entry.get("name", "")),
            filepath=rel,
        )
        apply_metadata_entry(ann, entry)
        if prototypes is None:
            prototypes = _DefinitionPrototypes(filepath)
        ann.prototype = prototypes.get(ann.name)
        results.append(ann)
    return results


class _DefinitionPrototypes:
    """Read function prototypes from C definitions, independently of anchors."""

    def __init__(self, filepath: Path, text: str | None = None) -> None:
        from rebrew.c_parser import function_signatures

        try:
            if text is None:
                text, _ = read_source_text(filepath)
        except OSError as exc:
            logger.warning("cannot read %s for its function prototypes: %s", filepath, exc)
            text = ""
        self._lines = text.splitlines()
        self._found = function_signatures(text) if text else {}

    def get(self, name: str) -> str:
        """The signature of *name*'s definition, or ``""``."""
        if not name:
            return ""
        if name not in self._found:
            self._found[name] = self._line_signature(name)
        return self._found[name]

    def _line_signature(self, name: str) -> str:
        lines = self._lines
        for index, line in enumerate(lines):
            stripped = line.strip()
            if f"{name}(" not in stripped.replace(" (", "(") or stripped.endswith(";"):
                continue
            following = next((ln.strip() for ln in lines[index + 1 :] if ln.strip()), "")
            if not (stripped.endswith("{") or following.startswith("{")):
                continue
            parsed = extract_function_name_from_line(stripped)
            if parsed is not None and parsed[0] == name:
                return " ".join(parsed[1].split())
        return ""


def _data_annotations_from_metadata(
    filepath: Path,
    target_name: str | None,
    base_dir: Path | None,
    metadata_dir: Path,
) -> list[SourceBinding]:
    """Data rows from ``rebrew-data.toml`` whose ``file`` matches.

    ``kind`` comes from the row, defaulting to ``DATA`` when unspecified.
    Data identities never compile as functions.
    The target filter matches function synthesis: another target's module
    is omitted when *target_name* is set.
    """
    from rebrew.metadata.data import data_rows_for_path
    from rebrew.metadata.functions import as_metadata_int

    rows = data_rows_for_path(metadata_dir, filepath)
    rel = rel_display_path(filepath, base_dir)
    results: list[SourceBinding] = []
    for module, va, entry in rows:
        if target_name and module and preset_module_key(module) != preset_module_key(target_name):
            continue
        raw_marker = entry.get("kind")
        if raw_marker:
            marker = str(raw_marker)
            if marker not in DATA_KINDS:
                continue
        else:
            marker = "DATA"
        ann = SourceBinding(
            va=va,
            module=module,
            kind=marker,
            name=str(entry.get("name") or ""),
            filepath=rel,
        )
        if "size" in entry:
            try:
                ann.size = as_metadata_int(entry["size"])
            except (TypeError, ValueError) as exc:
                logger.warning(
                    "rebrew-data.toml size for %s[0x%x] is not an integer (%r: %s); "
                    "leaving the synthesized annotation's size at 0",
                    module or "?",
                    va,
                    entry["size"],
                    exc,
                )
        if section := entry.get("section"):
            ann.section = str(section)
        if note := entry.get("note"):
            ann.note = str(note)
        results.append(ann)
    return results


def iter_source_bindings(
    sources: list[Path],
    *,
    target: str | None = None,
    metadata_dir: Path | None = None,
) -> list[tuple[Path, list[SourceBinding]]]:
    """Parse annotations from each source in *sources*, skipping failures.

    Returns ``(path, annotations)`` pairs, only for sources that yielded at
    least one annotation.  The shared batch-mode loader over
    :func:`read_source_bindings`.

    :param sources: List of paths returned by :func:`rebrew.sources.iter_sources`.
    :param target:  Optional marker string passed through to
        ``read_source_bindings`` (use :func:`rebrew.sources.target_marker` to obtain it).
    :param metadata_dir: Parent of ``reversed_dir`` where ``rebrew-functions.toml``
        lives.  When ``None``, metadata is not merged (only source annotations
        are parsed).
    """
    results: list[tuple[Path, list[SourceBinding]]] = []
    for src in sources:
        try:
            annos = read_source_bindings(src, target_name=target, metadata_dir=metadata_dir)
        except Exception:
            # Any per-source failure (parse error, I/O, encoding) silently
            # drops the whole function from verify/todo/status output — one
            # bad file must never abort a batch run.  Visible at WARNING.
            logger.warning("Skipping %s due to annotation parse error", src, exc_info=True)
            continue
        if annos:
            results.append((src, annos))
    return results


def read_function_fields(
    source_path: str | Path, metadata_dir: Path | None = None
) -> dict[str, str]:
    """Extract annotation metadata as a flat dict.

    Delegates to the canonical ``read_source_bindings`` parser so that every tool
    agrees on what the annotations say, then reshapes the result into the
    ``{KEY: value}`` dict format that callers expect. Marker entries map to
    the VA string only (for example ``{"FUNCTION": "0x10001a60"}``).

    Args:
        source_path: Path to the ``.c`` source file.
        metadata_dir: Directory containing ``rebrew-functions.toml``.
            When ``None``, metadata merging is skipped.

    """
    annos = read_source_bindings(Path(source_path), metadata_dir=metadata_dir)
    anno = annos[0] if annos else None
    if anno is None:
        return {}

    meta: dict[str, str] = {}
    # Map SourceBinding fields → the uppercase keys callers look up
    if anno.kind:
        meta[anno.kind] = f"0x{anno.va:08x}"
    if anno.status:
        meta["STATUS"] = anno.status
    if anno.size > 0:
        meta["SIZE"] = str(anno.size)
    if anno.cflags:
        meta["CFLAGS"] = anno.cflags
    if anno.toolchain:
        meta["TOOLCHAIN"] = anno.toolchain
    # SYMBOL is derived from function name — don't emit as annotation
    if anno.blocker:
        meta["BLOCKER"] = anno.blocker
    if anno.source:
        meta["SOURCE"] = anno.source
    if anno.note:
        meta["NOTE"] = anno.note
    if anno.ghidra:
        meta["GHIDRA"] = anno.ghidra
    # PROTOTYPE is derived from C definition — don't emit as annotation
    if anno.struct:
        meta["STRUCT"] = anno.struct
    if anno.callers:
        meta["CALLERS"] = anno.callers
    return meta


def span_contains_factory(spans: list[tuple[int, int]]) -> Callable[[int], bool]:
    """Build a bisect predicate over sorted ``(start, end)`` spans.

    Shared by the todo recommender and the BinSync exporter: heuristic
    discovery emits switch arms and split bodies as pseudo-functions, so a
    bare start-VA membership check is not enough — anything strictly inside
    an already-annotated function must be recognized as covered, including
    the tail of an outer span past a shorter annotation nested inside it.
    The returned predicate is O(log n) per probe.  Empty and inverted spans
    (``end <= start``) are dropped, and the rest are sorted internally, so
    *spans* may arrive in any order.
    """
    ordered = sorted((start, end) for start, end in spans if end > start)
    starts = [start for start, _end in ordered]
    # Greatest end among spans that start strictly before this index.  A probe
    # sits in some span exactly when that end, over the prefix of starts
    # before the probe, is past the probe.  Checking only the latest such
    # start hides the outer function once a nested one has ended.
    prefix_max_end = [0] * (len(ordered) + 1)
    for i, (_start, end) in enumerate(ordered):
        prefix_max_end[i + 1] = max(prefix_max_end[i], end)

    def contains(probe: int) -> bool:
        i = bisect.bisect_left(starts, probe)
        return i > 0 and prefix_max_end[i] > probe

    return contains


def library_inventory_bindings(metadata_dir: Path, base_dir: Path) -> list[SourceBinding]:
    """LIBRARY rows whose ``file`` is a ``library_*.h`` header.

    Identities live in ``rebrew-functions.toml`` and do not require a header
    on disk. Existing headers are read through :func:`library_bindings_for_file`
    so each row is counted once.
    """
    from rebrew.metadata.functions import apply_metadata_entry, load_metadata

    entries_by_key = load_metadata(metadata_dir, deepcopy=False)
    results: list[SourceBinding] = []
    for (module, va), entry in entries_by_key.items():
        if str(entry.get("kind", "")) != "LIBRARY":
            continue
        stored = str(entry.get("file", "")).replace("\\", "/")
        name = Path(stored).name
        if not name.startswith("library_") or not name.endswith(".h"):
            continue
        if (base_dir / stored).is_file() or (base_dir / name).is_file():
            continue
        ann = SourceBinding(
            va=va,
            module=module,
            kind="LIBRARY",
            symbol=str(entry.get("symbol", "")),
            name=str(entry.get("name", "")),
            filepath=stored,
        )
        apply_metadata_entry(ann, entry)
        results.append(ann)
    return results


def read_source_bindings(
    filepath: Path,
    target_name: str | None = None,
    base_dir: Path | None = None,
    metadata_dir: Path | None = None,
) -> list[SourceBinding]:
    """Read address anchors and canonical metadata; comments carry no state."""
    text, _ = read_source_text(filepath)
    return source_bindings(text, filepath, target_name, base_dir, metadata_dir)


def source_bindings(
    text: str,
    filepath: Path,
    target_name: str | None,
    base_dir: Path | None,
    metadata_dir: Path | None,
) -> list[SourceBinding]:
    """Join the pre-read source's address bindings with both metadata stores."""
    from rebrew.metadata.data import load_data_metadata
    from rebrew.metadata.functions import apply_metadata_entry, load_metadata

    forbidden = metadata_comments(text)
    if forbidden:
        line, forbidden_key = forbidden[0]
        raise ValueError(
            f"{filepath}:{line}: {forbidden_key} is not a source field; use dedicated metadata"
        )
    rows = _annotations_from_metadata(filepath, target_name, base_dir, metadata_dir)
    prototypes = _DefinitionPrototypes(filepath, text)
    for row in rows:
        if row.is_function:
            row.prototype = prototypes.get(row.name)
    indexed = {(preset_module_key(a.module), a.va, a.is_data): a for a in rows}
    functions = load_metadata(metadata_dir, deepcopy=False) if metadata_dir is not None else {}
    data = load_data_metadata(metadata_dir) if metadata_dir is not None else {}
    target = preset_module_key(target_name) if target_name else ""
    for anchor in parse_address_anchors(text):
        if target and preset_module_key(anchor.module) != target:
            continue
        is_data = anchor.kind == "DATA"
        key = (preset_module_key(anchor.module), anchor.va, is_data)
        existing = (
            indexed.get(key)
            if not is_data
            else next(
                (
                    row
                    for row in rows
                    if row.is_data
                    and row.module == anchor.module
                    and row.va == anchor.va
                    and (not row.name or row.name == anchor.name)
                ),
                None,
            )
        )
        if existing is not None:
            if existing.name and existing.name != anchor.name:
                raise ValueError(
                    f"{filepath}:{anchor.line}: address anchor names {anchor.name!r}, "
                    f"but the metadata names {existing.name!r}"
                )
            if not existing.name:
                existing.name = anchor.name
            if not is_data and not existing.symbol:
                existing.symbol = derive_c_symbol(anchor.name, anchor.prototype)
            existing.line = anchor.line
            existing.prototype = anchor.prototype
            continue
        ann = SourceBinding(
            va=anchor.va,
            module=anchor.module,
            name=anchor.name,
            symbol="" if is_data else derive_c_symbol(anchor.name, anchor.prototype),
            kind=anchor.kind,
            line=anchor.line,
            prototype=anchor.prototype,
            filepath=rel_display_path(filepath, base_dir),
        )
        stored = (data if is_data else functions).get((anchor.module, anchor.va), {})
        if is_data:
            from rebrew.metadata.data import merge_into_data_binding

            if metadata_dir is not None:
                merge_into_data_binding(ann, metadata_dir)
            if not stored.get("name") or stored.get("name") == anchor.name:
                ann.kind = str(stored.get("kind", "DATA"))
        else:
            apply_metadata_entry(ann, stored)
            ann.kind = str(stored.get("kind", "FUNCTION"))
        indexed[key] = ann
        rows.append(ann)
    return sorted(rows, key=lambda a: (a.line or 2**31, a.va, a.module))


def module_for_va(filepath: Path, va: int, metadata_dir: Path | None = None) -> str:
    """Resolve one unambiguous module from address bindings and stored rows."""
    modules = {
        a.module for a in read_source_bindings(filepath, metadata_dir=metadata_dir) if a.va == va
    }
    if len(modules) > 1:
        raise ValueError(f"{filepath}: address {va:#x} belongs to several target modules")
    return next(iter(modules), "")


def grow_function_extent(
    filepath: Path,
    new_size: int,
    target_va: int | None = None,
    metadata_dir: Path | None = None,
    module: str = "",
) -> bool:
    """Grow the stored function extent without modifying source."""
    from rebrew.metadata.functions import get_entry, update_field

    directory = metadata_dir if metadata_dir is not None else filepath.parent
    if target_va is None:
        candidates = [
            a for a in read_source_bindings(filepath, metadata_dir=directory) if a.is_function
        ]
        if len(candidates) != 1:
            raise ValueError("select one function address when updating its extent")
        target_va = candidates[0].va
        module = module or candidates[0].module
    module = module or module_for_va(filepath, target_va, directory)
    if not module:
        return False
    old_size = int(get_entry(directory, target_va, module=module).get("size", 0))
    if new_size <= old_size:
        return False
    update_field(directory, target_va, "size", new_size, module=module, updated_by="fix-sizes")
    return True


def set_binding_field(
    filepath: Path, va: int, key: str, new_value: str, metadata_dir: Path | None = None
) -> bool:
    """Write one canonical metadata field; source comments are never writers."""
    from rebrew.metadata.functions import (
        get_entry,
        is_metadata_key,
        update_field,
        update_source_status,
    )

    if not is_metadata_key(key):
        raise ValueError(f"{key!r} is not a function metadata field")
    directory = metadata_dir if metadata_dir is not None else filepath.parent
    module = module_for_va(filepath, va, directory)
    if key.upper() == "STATUS":
        return update_source_status(
            directory, new_value, module, va, clear_blockers=new_value in MATCHED_STATUSES
        )
    before = get_entry(directory, va, module=module).get(key.lower())
    update_field(directory, va, key.lower(), new_value, module=module)
    return get_entry(directory, va, module=module).get(key.lower()) != before


def remove_binding_field(
    filepath: Path, va: int, key: str, metadata_dir: Path | None = None
) -> bool:
    """Remove one canonical metadata field without modifying source."""
    from rebrew.metadata.functions import is_metadata_key, remove_field

    if not is_metadata_key(key):
        raise ValueError(f"{key!r} is not a function metadata field")
    directory = metadata_dir if metadata_dir is not None else filepath.parent
    return remove_field(directory, va, key.lower(), module=module_for_va(filepath, va, directory))


def library_bindings_for_file(
    filepath: Path, metadata_dir: Path | None = None
) -> list[SourceBinding]:
    """Read library identities from metadata; a header carries no inventory state."""
    if metadata_dir is None:
        return []
    return [
        a
        for a in _function_annotations_from_metadata(filepath, None, None, metadata_dir)
        if a.kind == "LIBRARY"
    ]


def split_address_sections(text: str) -> tuple[str, list[str]]:
    """Split source at declaration-bound address groups, preserving stacked targets."""
    anchors = parse_address_anchors(text)
    if not anchors:
        return text, []
    starts: dict[int, int] = {}
    for anchor in anchors:
        starts[anchor.definition_line] = min(
            starts.get(anchor.definition_line, anchor.line), anchor.line
        )
    boundaries = sorted(starts.values())
    lines = text.splitlines(keepends=True)
    return "".join(lines[: boundaries[0] - 1]), [
        "".join(lines[start - 1 : end - 1])
        for start, end in zip(boundaries, [*boundaries[1:], len(lines) + 1], strict=True)
    ]


def address_pairs(block: str) -> list[tuple[str, int]]:
    """Return the target/address pairs of declaration-bound address anchors."""
    return [(a.module, a.va) for a in parse_address_anchors(block)]


__all__ = [
    "DATA_KINDS",
    "FUNCTION_KINDS",
    "MIN_VALID_VA",
    "SYMBOL_KINDS",
    "SourceBinding",
    "address_pairs",
    "derive_c_symbol",
    "file_backed_by_metadata",
    "function_rows_for_file",
    "grow_function_extent",
    "has_skip_annotation",
    "iter_source_bindings",
    "kind_for_module",
    "library_bindings_for_file",
    "library_inventory_bindings",
    "make_function_binding",
    "min_valid_va_for",
    "module_for_va",
    "read_function_fields",
    "read_source_bindings",
    "remove_binding_field",
    "resolve_symbol",
    "set_binding_field",
    "source_bindings",
    "span_contains_factory",
    "split_address_sections",
]
