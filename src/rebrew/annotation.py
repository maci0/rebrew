"""annotation.py - Shared annotation parsing for rebrew.

Extracts the common annotation-parsing logic used across rebrew tools
so that there is a single source of truth for the decomp annotation format.

Annotation format (reccmp-compatible):
   ``// FUNCTION: SERVER 0x10008880`` marker line in ``.c`` files.
   Volatile metadata (STATUS, SIZE, CFLAGS, etc.) lives in ``rebrew-function.toml``.
"""

from __future__ import annotations

import contextlib
import functools
import logging
import re
import warnings
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Final

from rebrew.cli import MIN_VALID_VA
from rebrew.utils import atomic_write_text, read_source_text

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_PARSE_LOOKAHEAD_LINES: Final[int] = 20
"""Maximum lines scanned from file start for single-function parsing
(``parse_c_file``).  The multi-block parser (``parse_c_file_multi``)
scans the entire file instead.
"""

__all__ = [
    "Annotation",
    "VALID_MARKERS",
    "METADATA_KEYS",
    "has_skip_annotation",
    "module_for_va",
    "parse_c_file",
    "parse_c_file_multi",
    "parse_source_metadata",
    "resolve_symbol",
    "update_size_annotation",
]

# ---------------------------------------------------------------------------
# Valid sets
# ---------------------------------------------------------------------------

VALID_MARKERS = {"FUNCTION", "LIBRARY", "STUB", "GLOBAL", "DATA"}

# OPTIONAL_KEYS: only reccmp-compatible keys that are permitted inline.
# All rebrew-specific keys (ORIGIN, CFLAGS, SKIP, GLOBALS, BLOCKER, SOURCE,
# NOTE, SECTION, GHIDRA, BLOCKER_DELTA) must live in rebrew-function.toml
# — see METADATA_KEYS.
OPTIONAL_KEYS = {
    "ANALYSIS",  # reccmp compatibility (structural analysis note)
}
# Rebrew-specific keys that must live exclusively in the metadata (or, for the
# legacy pair, never inline at all).  Finding any of these inline fires lint
# W019.  Kept in sync with metadata.METADATA_FIELDS + LEGACY_KEYS: ANALYSIS and
# PROVE_CONSTRAINTS are metadata-routed fields, so an inline occurrence must
# warn just like STATUS/CFLAGS.
METADATA_KEYS: frozenset[str] = frozenset(
    {
        "STATUS",
        "ORIGIN",
        "CFLAGS",
        "SKIP",
        "GLOBALS",
        "BLOCKER",
        "BLOCKER_DELTA",
        "SOURCE",
        "NOTE",
        "SECTION",
        "GHIDRA",
        "SIZE",
        "ANALYSIS",
        "PROVE_CONSTRAINTS",
        "TOOLCHAIN",
    }
)
ALL_KNOWN_KEYS = OPTIONAL_KEYS | METADATA_KEYS | {"MARKER", "VA"}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# New format — line-comment style (the canonical output format).
# Quick match (no captures): used to test if a line is a marker line.
# Marker lines accept both ``// FUNCTION:`` (the default style) and
# ``/* FUNCTION: ... */`` (emitted for C89-strict 16-bit compilers like
# Turbo C 2.0 that reject ``//`` comments).
NEW_FUNC_RE = re.compile(
    r"(?://|/\*)\s*(?:FUNCTION|LIBRARY|STUB|GLOBAL|DATA):\s*\S+\s+0x[0-9a-fA-F]+"
)
# Full capture: extracts the marker type and VA.
NEW_FUNC_CAPTURE_RE = re.compile(
    r"(?://|/\*)\s*(?P<type>FUNCTION|LIBRARY|STUB|GLOBAL|DATA):\s*(?P<module>\S+)\s+(?P<va>0x[0-9a-fA-F]+)"
)
# Key-value comment lines (``// KEY: value``) — used by library headers
# (``// STATUS: EXACT``, ``// SIZE: 120``).  Metadata-owned fields are
# written to ``rebrew-function.toml``, not inline.
# Value capture strips a trailing ``*/`` for block-comment KVs
# (``/* SIZE: 64 */`` → "64", not "64 */").
NEW_KV_RE = re.compile(r"(?://|/\*)\s*(?P<key>[A-Z_]+):\s*(?P<value>.*?)\s*(?:\*/)?\s*$")

# Function name hint — bare ``// FunctionName`` comment after a marker line.
# Matches a single-word identifier (no colon, no spaces) that is not a KV key.
# Used to capture the actual function name in multi-function files where SYMBOL
# may be shared across blocks. Also allows stdcall decoration ``@N``,
# ``$`` (compiler-generated string labels), and ``?`` (MSVC C++ decoration).
FUNC_NAME_HINT_RE = re.compile(r"^//\s+(?P<name>[$?A-Za-z_][$?A-Za-z0-9_@]*)\s*$")

# Module-level compiled patterns for annotation mutation helpers.
# These were previously compiled inside functions on every call.
_MARKER_VA_RE = re.compile(
    r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*([\w.]+)\s+(0x[0-9a-fA-F]+)",
    re.IGNORECASE,
)
_MARKER_BLOCK_RE = re.compile(
    r"(?://|/\*)\s*(FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*\S+\s+(0x[0-9a-fA-F]+)"
)
_VA_ONLY_RE = re.compile(
    r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*\S+\s+(0x[0-9a-fA-F]+)"
)
_STDCALL_RE = re.compile(r"\b(?:__stdcall|WINAPI|CALLBACK|APIENTRY)\b")
_FASTCALL_RE = re.compile(r"\b__fastcall\b")

# Pre-compiled patterns for CFLAGS validation and template stripping.
_CFLAGS_GLUED_RE = re.compile(r"^/\w+/\w+")
_TEMPLATE_STRIP_RE = re.compile(r"<[^<>]*>")


# Process-lifetime memo for metadata-free parses (see parse_c_file_multi).
_PARSE_MEMO: dict[tuple[str, int, int], list[Annotation]] = {}
_PARSE_MEMO_MAX = 512


@functools.lru_cache(maxsize=64)
def _compile_key_pattern(key: str) -> re.Pattern[str]:
    """Return a compiled regex for matching an annotation key line."""
    escaped = re.escape(key)
    return re.compile(r"((?://|/\*)\s*" + escaped + r":\s*)(.*?)(?=\s*(?:\*/|\n|$))")


# ---------------------------------------------------------------------------
# Section splitting helper (shared by split.py and merge.py)
# ---------------------------------------------------------------------------


def split_annotation_sections(text: str) -> tuple[str, list[str]]:
    """Split annotated source into (preamble, function_blocks).

    Splits on ``// FUNCTION:`` (or LIBRARY/STUB/GLOBAL/DATA) marker lines,
    returning the text before the first marker as the preamble and each
    marker-delimited section as a block string.

    Any key-value comment lines (e.g. from library headers or preceding comments)
    immediately preceding a marker are included in that marker's block rather
    than the preamble, so that annotations stay with their function during
    merge/split operations.
    """
    lines = text.splitlines(keepends=True)
    marker_indexes: list[int] = []
    for idx, line in enumerate(lines):
        # Marker regex accepts `//` and `/*` (C89-strict 16-bit skeletons
        # emit `/* FUNCTION: ... */`) — quick reject avoids the `.strip()`
        # + regex on the vast majority of source lines.
        stripped = line.lstrip()
        if not (stripped.startswith("//") or stripped.startswith("/*")):
            continue
        if NEW_FUNC_CAPTURE_RE.match(stripped.rstrip()):
            marker_indexes.append(idx)

    if not marker_indexes:
        return text, []

    # For each marker, scan backwards to include preceding annotation
    # key-value lines (// KEY: value) in the block.  Blank lines between
    # annotations and marker are consumed too.  The scan never goes past
    # the previous marker to avoid stealing from another block.
    adjusted_starts: list[int] = []
    for i, marker_idx in enumerate(marker_indexes):
        start = marker_idx
        lower_bound = marker_indexes[i - 1] if i > 0 else 0
        while start > lower_bound:
            prev_line = lines[start - 1].strip()
            if not prev_line:
                start -= 1
                continue
            if NEW_KV_RE.match(prev_line):
                start -= 1
            else:
                break
        adjusted_starts.append(start)

    preamble_lines = lines[: adjusted_starts[0]]
    blocks: list[str] = []
    for i, start in enumerate(adjusted_starts):
        end = adjusted_starts[i + 1] if i + 1 < len(adjusted_starts) else len(lines)
        blocks.append("".join(lines[start:end]))

    # Post-process: rescue orphaned annotation KV lines from the preamble.
    # This happens when a source file has annotations at the top separated
    # from the FUNCTION marker by non-annotation lines (includes, externs).
    # Without this fix, merge would discard those annotations during preamble
    # deduplication.
    if blocks and preamble_lines:
        rescued: list[str] = []
        kept: list[str] = []
        for line in preamble_lines:
            stripped = line.strip()
            if stripped and NEW_KV_RE.match(stripped):
                rescued.append(line)
            else:
                kept.append(line)
        if rescued:
            preamble_lines = kept
            blocks[0] = "".join(rescued) + blocks[0]

    preamble = "".join(preamble_lines)
    return preamble, blocks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalize_status(raw: str) -> str:
    """Map old-format status strings to canonical values.

    Check order matters for strings that are substrings of each other:
    ``EXACT`` must be tested first so that e.g. ``"EXACT_MATCH"`` maps to
    ``"EXACT"`` and not ``"RELOC"``.  ``NEAR_MATCHING`` is tested before
    ``RELOC`` so that it is not accidentally matched by the ``"RELOC"``
    substring check (``"NEAR_MATCHING"`` does not contain ``"RELOC"`` but
    the ordering is preserved for safety).  ``PROVEN`` is included before
    the generic fallthrough so old-format strings like ``"PROVEN_MATCH"``
    are normalised to ``"PROVEN"`` rather than returned verbatim.
    """
    s = raw.strip().upper()
    if "EXACT" in s:
        return "EXACT"
    if "NEAR_MATCHING" in s:
        return "NEAR_MATCHING"
    if "RELOC" in s:
        return "RELOC"
    if "STUB" in s:
        return "STUB"
    if "PROVEN" in s:
        return "PROVEN"
    return s


def normalize_cflags(raw: str) -> str:
    """Clean up cflags string."""
    return raw.strip().rstrip(",").strip()


def marker_for_module(module: str, status: str, library_modules: set[str] | None = None) -> str:
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


def has_skip_annotation(filepath: Path, metadata_dir: Path | None = None) -> bool:
    """Return True if a function in *filepath* is marked as skippable.

    Checks ``rebrew-function.toml`` metadata for a ``skip`` field on THIS
    file's own (module, va) entries only — a skip anywhere else in the
    project must not empty ``match --all``'s stub collection.
    Returns ``False`` immediately when *metadata_dir* is ``None``.
    """
    if metadata_dir is None:
        return False
    try:
        from rebrew.metadata import load_metadata

        entries = load_metadata(metadata_dir)
        for ann in parse_c_file_multi(filepath):
            raw_skip = entries.get((ann.module, ann.va), {}).get("skip", "")
            if raw_skip and str(raw_skip).strip().lower() not in ("", "0", "false", "no"):
                return True
    except Exception:  # noqa: BLE001 — metadata read failure is non-fatal
        logger.debug("Metadata read failed for skip check in %s", metadata_dir, exc_info=True)
    return False


def resolve_symbol(entry: Annotation, filepath: Path) -> str:
    """Resolve a usable symbol name from an annotation, falling back to filename."""
    symbol = entry.symbol
    if symbol and symbol != "?":
        return symbol
    return "_" + filepath.stem


# ---------------------------------------------------------------------------
# Data construction
# ---------------------------------------------------------------------------

# Field name mapping for dict-like access (handles "globals" → globals_list)
_FIELD_ALIASES: Final[dict[str, str]] = {"globals": "globals_list"}


@dataclass
class Annotation:
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
    toolchain: str = ""  # per-function toolchain override (e.g. "msvc5")
    marker_type: str = ""
    filepath: str = ""
    source: str = ""
    blocker: str = ""
    blocker_delta: int | None = None
    note: str = ""
    ghidra: str = ""
    prototype: str = ""
    struct: str = ""
    callers: str = ""
    inline_error: str = ""
    globals_list: list[str] = field(default_factory=list)
    section: str = ""  # .data, .rdata, .bss — used by DATA annotations
    line: int = 0  # 1-based line number of the marker in the source file
    prove_constraints: dict[str, Any] = field(default_factory=dict)

    # -- Dict-like access and field aliases --

    def __getitem__(self, key: str) -> Any:
        """Return the field value for *key* (supports field aliases)."""
        attr = _FIELD_ALIASES.get(key, key)
        try:
            return getattr(self, attr)
        except AttributeError:
            raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        """Set the field *key* to *value* (supports field aliases)."""
        attr = _FIELD_ALIASES.get(key, key)
        if hasattr(self, attr):
            object.__setattr__(self, attr, value)
        else:
            raise KeyError(key)

    # Class-level cache for field names — computed once, not per __contains__ call.
    _field_names: frozenset[str] | None = None

    def __contains__(self, key: str) -> bool:
        """Return True if *key* (or its alias) is a field of this Annotation."""
        attr = _FIELD_ALIASES.get(key, key)
        if Annotation._field_names is None:
            Annotation._field_names = frozenset(f.name for f in fields(self))
        return attr in Annotation._field_names

    def get(self, key: str, default: Any = None) -> Any:
        """Return the value for *key*, or *default* if not present."""
        try:
            return self[key]
        except KeyError:
            return default

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
            "marker_type": self.marker_type,
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
            "inline_error": self.inline_error,
            "line": self.line,
        }
        if self.section:
            d["section"] = self.section
        if self.prove_constraints:
            d["prove_constraints"] = self.prove_constraints
        return d

    def validate(
        self,
        filepath: Path | None = None,
        library_modules: set[str] | None = None,
        min_va: int = MIN_VALID_VA,
    ) -> tuple[list[str], list[str]]:
        """Validate annotation fields. Returns (errors, warnings)."""
        errors: list[str] = []
        warnings: list[str] = []

        if self.marker_type and self.marker_type not in VALID_MARKERS:
            errors.append(f"Invalid marker type: {self.marker_type}")

        if self.inline_error:
            errors.append(
                f"Multiple annotations found on the same line: '{self.inline_error}' (please separate them into different lines)"
            )

        if self.va < min_va:
            errors.append(f"VA 0x{self.va:x} is suspicious (below 0x{min_va:x})")

        if self.size <= 0:
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
        # rebrew-function.toml); only library-module mismatches are flagged.
        _lib = library_modules or set()
        if self.module in _lib:
            expected_marker = "LIBRARY"
            marker_ok = self.marker_type == "LIBRARY"
        elif self.status == "STUB":
            expected_marker = "FUNCTION"
            marker_ok = self.marker_type in ("FUNCTION", "STUB")
        else:
            expected_marker = "FUNCTION"
            marker_ok = self.marker_type == "FUNCTION"
        if self.marker_type and not marker_ok:
            warnings.append(
                f"Marker {self.marker_type} inconsistent with module {self.module!r} "
                f"(expected {expected_marker})"
            )

        if self.status == "STUB" and not self.blocker:
            warnings.append("STUB function missing BLOCKER annotation")

        if self.module in _lib and not self.source:
            warnings.append(
                f"Library module {self.module!r} missing SOURCE annotation "
                "(reference file, e.g. SBHEAP.C:195 or deflate.c)"
            )

        if self.status == "NEAR_MATCHING" and self.marker_type == "STUB":
            warnings.append(f"Contradictory: status is {self.status} but marker is STUB")

        return errors, warnings


def make_func_entry(
    va: int,
    size: int,
    name: str,
    symbol: str,
    status: str,
    cflags: str,
    marker_type: str,
    filepath: str,
    module: str = "",
    source: str = "",
    blocker: str = "",
    note: str = "",
    inline_error: str = "",
    globals_list: list[str] | None = None,
) -> Annotation:
    """Create an Annotation instance."""
    return Annotation(
        va=va,
        size=size,
        name=name,
        symbol=symbol,
        module=module,
        status=status,
        cflags=cflags,
        marker_type=marker_type,
        filepath=filepath,
        source=source,
        blocker=blocker,
        note=note,
        inline_error=inline_error,
        globals_list=globals_list or [],
    )


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def module_for_va(filepath: Path, va: int) -> str:
    """Scan *filepath* for a marker line for *va* and return its module name.

    Returns the module name (e.g. ``"SERVER"``) or an empty string if not found.
    Used by annotation mutation helpers to route metadata writes to the correct key.
    """
    try:
        text, _ = read_source_text(filepath)
    except OSError:
        return ""
    for line in text.splitlines():
        m = _MARKER_VA_RE.search(line)
        if m and int(m.group(2), 16) == va:
            return m.group(1)
    return ""


def update_size_annotation(
    filepath: Path, new_size: int, target_va: int | None = None, metadata_dir: Path | None = None
) -> bool:
    """Update the SIZE for a function — always writes to the metadata.

    Writes *new_size* to the ``rebrew-function.toml`` metadata at *metadata_dir*
    (only increasing, never shrinking).

    *target_va* is required for multi-function files; for single-function files
    it can be omitted and will be inferred from the marker line.

    Returns True if any change was made, False otherwise.

    Args:
        filepath: Path to the .c source file.
        new_size: New SIZE value.
        target_va: VA of the specific function to update.
        metadata_dir: Root directory for ``rebrew-function.toml``.
            When ``None``, falls back to ``filepath.parent``.

    """
    from rebrew.metadata import get_entry, update_field

    # Resolve VA if not provided — scan file for the first marker line
    va = target_va
    if va is None:
        try:
            text, _ = read_source_text(filepath)
        except OSError as e:
            warnings.warn(f"Cannot read {filepath} for size update: {e}", stacklevel=2)
            return False
        for line in text.splitlines():
            m = _VA_ONLY_RE.search(line)
            if m:
                va = int(m.group(1), 16)
                break

    if va is None:
        return False

    module = module_for_va(filepath, va)
    _dir = metadata_dir if metadata_dir is not None else filepath.parent
    entry = get_entry(_dir, va, module=module)
    old_size = int(entry.get("size", 0))
    if new_size <= old_size:
        return False
    update_field(_dir, va, "size", new_size, module=module)
    return True


# __stdcall parameter types → stack size in bytes (MSVC6 x86 conventions).
# Everything is promoted to at least 4 bytes on the stack; doubles and __int64 are 8.
_STDCALL_TYPE_SIZES: dict[str, int] = {
    "double": 8,
    "__int64": 8,
    "long long": 8,
    "unsigned long long": 8,
    "LONGLONG": 8,
    "ULONGLONG": 8,
}
_STDCALL_DEFAULT_SIZE = 4  # int, char, short, pointers, etc. all push 4 bytes


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
    cleaned = re.sub(r"__declspec\s*\([^)]*\)", "", proto)
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

    total = 0
    for param in params_str.split(","):
        param = param.strip()
        if not param:
            continue
        # Check if any known large type is in the parameter declaration
        matched_size = _STDCALL_DEFAULT_SIZE
        for type_name, size in _STDCALL_TYPE_SIZES.items():
            if type_name in param:
                matched_size = size
                break
        total += matched_size

    return total


def _kv_to_annotation(
    kv: dict[str, str],
    marker_type: str,
    va: int,
    module: str,
) -> Annotation:
    """Convert a parsed key-value dict into an Annotation instance.

    Name resolution priority:
    1. ``_C_FUNC_NAME`` — extracted from the actual C function definition
    2. ``_FUNC_NAME_HINT`` — bare ``// FunctionName`` comment after the marker
    3. Empty string (downstream code will fall back to filename stem)

    Symbol is derived as ``"_" + name`` for __cdecl (default), or
    ``"_" + name + "@N"`` for __stdcall/WINAPI functions where N is the
    parameter stack size.
    Prototype is extracted from the actual C function definition line when
    available.

    ``// SYMBOL:`` and ``// PROTOTYPE:`` inline annotations are not supported;
    they are ignored during parsing and will trigger W010 (unknown key) in lint.
    """
    c_func_name = kv.get("_C_FUNC_NAME", "")
    c_func_proto = kv.get("_C_FUNC_PROTO", "")
    func_name_hint = kv.get("_FUNC_NAME_HINT", "")

    # Derive name: prefer C definition > hint comment
    if c_func_name:
        name = c_func_name
    elif func_name_hint:
        name = func_name_hint
    else:
        name = ""

    # Derive symbol: "_" + name for __cdecl (default), "_" + name + "@N" for
    # __stdcall/WINAPI, "@" + name + "@N" for __fastcall (ecx/edx args are
    # still counted in the decoration's N on MSVC).
    symbol = "_" + name if name else ""
    if name and c_func_proto and _FASTCALL_RE.search(c_func_proto):
        param_size = _calc_stdcall_param_size(c_func_proto)
        if param_size is not None:
            symbol = f"@{name}@{param_size}"
    elif name and c_func_proto and _STDCALL_RE.search(c_func_proto):
        # Calculate parameter stack size from prototype for decorated name
        param_size = _calc_stdcall_param_size(c_func_proto)
        if param_size is not None:
            symbol = f"_{name}@{param_size}"

    # Derive prototype from C definition
    prototype = c_func_proto

    size_str = kv.get("SIZE", "0")
    try:
        size = int(size_str)
    except ValueError:
        size = 0

    blocker_delta: int | None = None
    raw_delta = kv.get("BLOCKER_DELTA", "")
    if raw_delta:
        with contextlib.suppress(ValueError):
            blocker_delta = int(raw_delta)

    raw_globals = kv.get("GLOBALS", "")
    globals_list = [g.strip() for g in raw_globals.split(",") if g.strip()] if raw_globals else []

    ann = make_func_entry(
        va=va,
        size=size,
        name=name,
        symbol=symbol,
        module=module,
        status=kv.get("STATUS", "STUB"),
        cflags=kv.get("CFLAGS", ""),
        toolchain=kv.get("TOOLCHAIN", ""),
        marker_type=marker_type,
        filepath="",
        source=kv.get("SOURCE", ""),
        blocker=kv.get("BLOCKER", ""),
        note=kv.get("NOTE", ""),
        inline_error=kv.get("_INLINE_ERROR", ""),
        globals_list=globals_list,
    )
    ann.section = kv.get("SECTION", "")
    ann.blocker_delta = blocker_delta
    ann.ghidra = kv.get("GHIDRA", "")
    ann.prototype = prototype
    ann.struct = kv.get("STRUCT", "")
    ann.callers = kv.get("CALLERS", "")
    return ann


def parse_new_format(lines: list[str]) -> Annotation | None:
    """Try to parse new reccmp-style annotations from first lines.

    State machine: scans the provided *lines* looking for a marker line
    (``// FUNCTION: SERVER 0x...``), then collects subsequent key-value
    comment lines until a non-annotation line is hit.  Non-annotation
    preamble lines before the marker are tolerated.  Returns None if
    no valid marker line is found.  (The caller typically limits *lines*
    to the first ``_PARSE_LOOKAHEAD_LINES`` of the file.)
    """
    marker_type = None
    va = None
    module = ""
    kv: dict[str, str] = {}
    in_annotation_block = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Fast pre-filter: marker/KV/hint regexes start with `//` or `/*`
        # (block-comment markers are emitted for C89-strict compilers); most
        # source lines are C code and can skip the regex calls entirely.
        is_comment = stripped.startswith("//") or stripped.startswith("/*")

        # Check for marker
        m = NEW_FUNC_CAPTURE_RE.match(stripped) if is_comment else None
        if m:
            new_type = m.group("type")
            # If we already found a code-bearing marker (FUNCTION/LIBRARY/STUB),
            # don't let a GLOBAL/DATA marker overwrite it — treat it as a
            # non-annotation line instead.
            if marker_type in ("FUNCTION", "LIBRARY", "STUB") and new_type in ("GLOBAL", "DATA"):
                if in_annotation_block:
                    break
                continue
            marker_type = new_type
            va = int(m.group("va"), 16)
            module = m.group("module")
            in_annotation_block = True

            # If there's inline stuff after the VA, stash it in a special internal field to lint later
            if stripped.count("//") > 1:
                kv["_INLINE_ERROR"] = stripped
            continue

        # Check for key-value
        m2 = NEW_KV_RE.match(stripped) if is_comment else None
        if m2:
            key = m2.group("key").upper()
            val = m2.group("value").strip()
            kv[key] = val
            continue

        # Check for function name hint: bare "// FunctionName" after marker
        if is_comment and in_annotation_block and "_FUNC_NAME_HINT" not in kv:
            m3 = FUNC_NAME_HINT_RE.match(stripped)
            if m3:
                kv["_FUNC_NAME_HINT"] = m3.group("name")
                continue

        if not in_annotation_block:
            continue

        # Try to extract function name from C definition line.
        # Skip forward declarations (lines ending with ';') — only match
        # actual function definitions (lines ending with '{' or just a signature
        # without a semicolon).
        if "_C_FUNC_NAME" not in kv and not stripped.rstrip().endswith(";"):
            from rebrew.c_parser import extract_function_name_from_line

            func_result = extract_function_name_from_line(stripped)
            if func_result:
                kv["_C_FUNC_NAME"] = func_result[0]
                kv["_C_FUNC_PROTO"] = func_result[1]

        break

    if marker_type is None or va is None:
        return None

    return _kv_to_annotation(kv, marker_type, va, module)


def _relative_filepath(filepath: Path, base_dir: Path | None) -> str:
    """Return the filepath relative to *base_dir*, or just the filename."""
    if base_dir is not None:
        try:
            return str(filepath.relative_to(base_dir))
        except ValueError:
            pass
    return filepath.name


def parse_c_file(
    filepath: Path,
    target_name: str | None = None,
    base_dir: Path | None = None,
) -> Annotation | None:
    """Parse a decomp .c file for annotations.

    Parses ``// FUNCTION: MODULE 0xVA`` marker lines from the first 20 lines.
    Does **not** merge metadata from ``rebrew-function.toml`` — use
    ``parse_c_file_multi()`` with *metadata_dir* for metadata overlay.

    Sets ``filepath`` on the returned Annotation for downstream use.
    When *base_dir* is given the stored path is relative to it (e.g.
    ``"zlib/zlib_adler32.c"``); otherwise only the bare filename is kept.
    """
    try:
        text, _ = read_source_text(filepath)
    except OSError:
        return None

    lines = text.splitlines()
    if not lines:
        return None

    rel = _relative_filepath(filepath, base_dir)

    # Only use new format (multi-line) — preferred, canonical output
    entry = parse_new_format(lines[:_PARSE_LOOKAHEAD_LINES])
    if entry is not None:
        if target_name and entry.module and entry.module.lower() != target_name.lower():
            return None
        entry.filepath = rel
        return entry

    return None


def parse_new_format_multi(lines: list[str]) -> list[Annotation]:
    """Parse ALL reccmp-style annotation blocks from a file's lines.

    Scans the full file for ``// FUNCTION:`` markers.  Each marker starts
    a new annotation block; subsequent ``// KEY: value`` lines attach to
    the current block.  Non-annotation lines (code) between blocks are
    skipped — they don't terminate scanning.

    Supports both orderings:
    - Marker first, then key-value lines (original rebrew format)
    - Key-value lines first, then marker (reccmp-compatible format)

    Returns a list of Annotations (may be empty).
    """
    results: list[Annotation] = []
    current_marker_type: str | None = None
    current_va: int | None = None
    current_module = ""
    current_kv: dict[str, str] = {}
    pending_kv: dict[str, str] = {}
    seen_code_after_marker: bool = False
    current_line: int = 0  # 1-based line number of the current marker

    def _flush() -> None:
        nonlocal current_marker_type, current_va, current_module, current_kv, pending_kv
        if current_marker_type is None or current_va is None:
            return
        ann = _kv_to_annotation(current_kv, current_marker_type, current_va, current_module)
        ann.line = current_line
        results.append(ann)
        pending_kv = {}

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        # Fast pre-filter: marker/KV/hint regexes all require a leading `//`;
        # most C source lines are code and can skip the regex calls entirely.
        is_comment = stripped.startswith("//") or stripped.startswith("/*")

        # Check for a new marker line (starts a new block)
        m = NEW_FUNC_CAPTURE_RE.match(stripped) if is_comment else None
        if m and m.group("type") in ("FUNCTION", "LIBRARY", "STUB", "GLOBAL", "DATA"):
            # Save pending KV before flush (flush clears pending_kv)
            saved_pending = dict(pending_kv)
            # Flush the previous block before starting a new one
            _flush()
            current_marker_type = m.group("type")
            current_va = int(m.group("va"), 16)
            current_module = m.group("module")
            current_line = lineno
            # Merge any pending key-value lines that appeared before this marker
            current_kv = saved_pending
            pending_kv = {}
            seen_code_after_marker = False

            if stripped.count("//") > 1:
                current_kv["_INLINE_ERROR"] = stripped
            continue

        # Collect key-value lines
        m2 = NEW_KV_RE.match(stripped) if is_comment else None
        if m2:
            key = m2.group("key").upper()
            val = m2.group("value").strip()
            if current_marker_type is not None and not seen_code_after_marker:
                # KV immediately after marker — attach to current block
                current_kv[key] = val
            else:
                # Before any marker, or after code — buffer for the next block
                pending_kv[key] = val
            continue

        # Check for function name hint: bare "// FunctionName" after marker
        if is_comment and current_marker_type is not None and not seen_code_after_marker:
            m3 = FUNC_NAME_HINT_RE.match(stripped)
            if m3 and "_FUNC_NAME_HINT" not in current_kv:
                current_kv["_FUNC_NAME_HINT"] = m3.group("name")
                continue

        # Try to extract function name from C definition line.
        # Skip forward declarations (lines ending with ';') — only match
        # actual function definitions.  Only FUNCTION/LIBRARY/STUB blocks take
        # a C-definition name: a DATA/GLOBAL block followed by a function
        # definition (e.g. extern decls then the real function) would
        # otherwise inherit that function's name, misnaming the data symbol
        # and corrupting symbol→VA resolution (guild-rebrew
        # DispatchLogOutput DATA entry got the function name).
        if (
            current_marker_type in ("FUNCTION", "LIBRARY", "STUB")
            and "_C_FUNC_NAME" not in current_kv
            and not stripped.rstrip().endswith(";")
        ):
            from rebrew.c_parser import extract_function_name_from_line

            func_result = extract_function_name_from_line(stripped)
            if func_result:
                current_kv["_C_FUNC_NAME"] = func_result[0]
                current_kv["_C_FUNC_PROTO"] = func_result[1]

        # Non-annotation line: mark that we've seen code, but keep pending_kv
        # so annotations survive through #include/extern/typedef lines until
        # the next FUNCTION marker.
        if current_marker_type is not None:
            seen_code_after_marker = True

    # Flush the last block
    _flush()
    if pending_kv:
        logger.debug("Discarding orphaned KV annotations: %s", pending_kv)
    return results


def parse_c_file_multi(
    filepath: Path,
    target_name: str | None = None,
    base_dir: Path | None = None,
    metadata_dir: Path | None = None,
) -> list[Annotation]:
    """Parse ALL annotation blocks from a decomp .c file.

    Returns a list of Annotations, one per ``// FUNCTION:`` marker found
    in the file.  For single-function files this returns a one-element list.
    Returns an empty list if no annotations are found.

    When *metadata_dir* is provided each returned Annotation is overlaid with
    values from that directory's ``rebrew-function.toml`` (metadata wins for volatile
    fields like STATUS, SIZE, CFLAGS, BLOCKER, NOTE, GHIDRA).  Pass the real
    metadata root (``cfg.metadata_dir`` — the parent of ``reversed_dir``) as
    *metadata_dir*; ``filepath.parent`` only works for single-source layouts
    and silently no-ops the merge when the metadata file lives elsewhere.

    Sets ``filepath`` on each returned Annotation.  When *base_dir* is
    given the stored path is relative to it; otherwise the bare filename.
    """
    try:
        text, _ = read_source_text(filepath)
    except OSError:
        return []

    # Metadata-free parses are deterministic per file content — memoize
    # them for the process lifetime so repeated scans (verify's
    # prepare_entries + build_name_to_va, test --all) don't parse the same
    # source tree twice.  The metadata overlay (metadata_dir) is applied
    # per call and never memoized (it can change independently of source).
    if metadata_dir is None and base_dir is None:
        try:
            st = filepath.stat()
            key = (str(filepath), st.st_mtime_ns, st.st_size)
        except OSError:
            key = None
        if key is not None:
            cached = _PARSE_MEMO.get(key)
            if cached is not None:
                return cached
        result = _parse_c_file_text(text, filepath, target_name, base_dir, metadata_dir)
        if key is not None:
            if len(_PARSE_MEMO) >= _PARSE_MEMO_MAX:
                _PARSE_MEMO.clear()
            _PARSE_MEMO[key] = result
        return result
    return _parse_c_file_text(text, filepath, target_name, base_dir, metadata_dir)


def _parse_c_file_text(
    text: str,
    filepath: Path,
    target_name: str | None,
    base_dir: Path | None,
    metadata_dir: Path | None,
) -> list[Annotation]:
    try:
        lines = text.splitlines()
    except Exception:  # noqa: BLE001 — degenerate input
        return []
    if not lines:
        return []

    rel = _relative_filepath(filepath, base_dir)

    # Try multi-block new format (scans entire file)
    entries = parse_new_format_multi(lines)
    if entries:
        filtered_entries = [
            entry
            for entry in entries
            if not (target_name and entry.module and entry.module.lower() != target_name.lower())
        ]
        for entry in filtered_entries:
            entry.filepath = rel
        if metadata_dir is not None:
            from rebrew.metadata import merge_into_annotation

            for entry in filtered_entries:
                merge_into_annotation(entry, metadata_dir)
        return filtered_entries

    return []


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------


def parse_source_metadata(
    source_path: str | Path, metadata_dir: Path | None = None
) -> dict[str, str]:
    """Extract annotation metadata as a flat dict.

    Delegates to the canonical ``parse_c_file_multi`` parser so that every tool
    agrees on what the annotations say, then reshapes the result into the
    ``{KEY: value}`` dict format that callers expect. Marker entries map to
    the VA string only (for example ``{"FUNCTION": "0x10001a60"}``).

    Args:
        source_path: Path to the ``.c`` source file.
        metadata_dir: Directory containing ``rebrew-function.toml``.
            When ``None``, metadata merging is skipped.

    """
    annos = parse_c_file_multi(Path(source_path), metadata_dir=metadata_dir)
    anno = annos[0] if annos else None
    if anno is None:
        return {}

    meta: dict[str, str] = {}
    # Map Annotation fields → the uppercase keys callers look up
    if anno.marker_type:
        # e.g. meta["FUNCTION"] = "SERVER 0x10001a60"
        va_hex = f"0x{anno.va:08x}"
        meta[anno.marker_type] = va_hex
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


def update_annotation_key(
    filepath: Path, va: int, key: str, new_value: str, metadata_dir: Path | None = None
) -> bool:
    """Update or add an annotation key for a specific VA.

    For metadata-owned keys (STATUS, SIZE, CFLAGS, BLOCKER, NOTE,
    GHIDRA, …) the value is written to the ``rebrew-function.toml`` metadata
    at *metadata_dir*, leaving the ``.c`` file untouched.

    Args:
        filepath: Path to the ``.c`` source file.
        va: Virtual address integer.
        key: Annotation key (e.g. ``"STATUS"``, ``"CFLAGS"``).
        new_value: New value string.
        metadata_dir: Directory containing ``rebrew-function.toml``.
            Required for metadata-owned keys.

    Returns True if any write was made, False otherwise.

    """
    from rebrew.metadata import is_metadata_key, update_source_status
    from rebrew.metadata_model import _FIELD_TO_ATTR, MetadataEntry

    if is_metadata_key(key):
        module = module_for_va(filepath, va)
        _dir = metadata_dir if metadata_dir is not None else filepath.parent
        if key.upper() == "STATUS":
            update_source_status(_dir, new_value, module, va, force=True)
        else:
            # Typed, validated write via the metadata facade: key case is
            # normalized, size/blocker_delta are coerced to int, and unknown
            # /file-only keys raise instead of silently mis-routing.
            entry = MetadataEntry.load(_dir, va, module)
            attr = _FIELD_TO_ATTR.get(key.lower())
            existing = getattr(entry, attr, None) if attr is not None else None
            # Idempotent: a write with the same value is a no-op (False).
            if existing is not None and str(existing) == str(new_value):
                return False
            entry.apply(_dir, **{key: new_value})
        return True
    try:
        text, encoding = read_source_text(filepath)
    except OSError as e:
        warnings.warn(f"Cannot read {filepath} for annotation update: {e}", stacklevel=2)
        return False

    lines = text.splitlines(keepends=True)
    in_target_block = False
    last_annotation_idx = -1
    modified = False
    _key_pattern = _compile_key_pattern(key)

    for i, line in enumerate(lines):
        # Check for marker: // FUNCTION: GAME 0x1000 or STUB or DATA etc.
        marker_match = _MARKER_BLOCK_RE.search(line)
        if marker_match:
            found_va = int(marker_match.group(2), 16)
            if in_target_block and found_va != va:
                # A new annotation block started after our target block.
                # Stop here — edits must not bleed into subsequent blocks.
                break
            in_target_block = found_va == va

        if in_target_block:
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                last_annotation_idx = i

            sym_match = _key_pattern.search(line)
            if sym_match:
                old_val = sym_match.group(2).strip()
                if old_val == new_value:
                    return False
                lines[i] = (
                    line[: sym_match.start()]
                    + sym_match.group(1)
                    + new_value
                    + line[sym_match.end() :]
                )
                modified = True
                break

            if not (
                line.strip().startswith("//") or line.strip().startswith("/*") or line.strip() == ""
            ):
                if last_annotation_idx != -1:
                    lines.insert(last_annotation_idx + 1, f"// {key}: {new_value}\n")
                    modified = True
                break

    # If the file ends with the annotation block and we didn't insert
    if in_target_block and not modified and last_annotation_idx != -1:
        lines.insert(last_annotation_idx + 1, f"// {key}: {new_value}\n")
        modified = True

    if modified:
        atomic_write_text(filepath, "".join(lines), encoding=encoding)
        return True

    return False


# ---------------------------------------------------------------------------
# Library header parser
# ---------------------------------------------------------------------------


def parse_library_header(
    filepath: Path,
    target_name: str | None = None,
) -> list[Annotation]:
    """Parse a ``library_*.h`` file for LIBRARY markers.

    Supports two formats per entry:

    **Minimal** (reccmp-compatible, identified-only functions)::

        // LIBRARY: SERVER 0x1001A18A
        // _fflush

    **Extended** (rebrew-only KV lines after the symbol — ignored by reccmp)::

        // LIBRARY: SERVER 0x10050000
        // _deflate
        // STATUS: NEAR_MATCHING
        // SIZE: 120
        // CFLAGS: /O2 /Gd
        // SOURCE: deflate.c

    reccmp's parser reads the marker + symbol, then moves on; the KV lines
    are invisible to it.  Rebrew captures them to support library functions
    that are actively compiled and matched from reference source.

    Returns a list of Annotations with marker_type=LIBRARY.  Entries
    without explicit STATUS default to EXACT.
    """
    try:
        text, _ = read_source_text(filepath)
    except OSError:
        return []

    lines = text.splitlines()
    if not lines:
        return []

    results: list[Annotation] = []

    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        m = NEW_FUNC_CAPTURE_RE.match(stripped)
        if m and m.group("type") == "LIBRARY":
            module = m.group("module")
            va = int(m.group("va"), 16)

            # NOTE: no target-module filter here — the LIBRARY module is the
            # library name (MSVCRT, ZLIB, ...), not the project marker, so a
            # filter against target_name would silently drop every entry.

            # Look for symbol on next non-blank comment line
            symbol = ""
            j = i + 1
            while j < len(lines):
                next_line = lines[j].strip()
                if not next_line:
                    j += 1
                    continue
                if next_line.startswith("//"):
                    # Symbol line if it's NOT a KV annotation
                    kv_match = NEW_KV_RE.match(next_line)
                    if not kv_match:
                        symbol = next_line.lstrip("/").strip()
                        j += 1
                break

            # Collect optional KV lines after the symbol (rebrew extension)
            kv: dict[str, str] = {}
            while j < len(lines):
                kv_line = lines[j].strip()
                if not kv_line:
                    j += 1
                    continue
                kv_match = NEW_KV_RE.match(kv_line)
                if kv_match:
                    kv[kv_match.group("key").upper()] = kv_match.group("value").strip()
                    j += 1
                else:
                    break

            # Build annotation — KV values override defaults
            size = 0
            size_str = kv.get("SIZE", "")
            if size_str:
                with contextlib.suppress(ValueError):
                    size = int(size_str)

            results.append(
                Annotation(
                    va=va,
                    size=size,
                    name=symbol.lstrip("_") if symbol else "",
                    symbol=symbol,
                    module=module,
                    status=kv.get("STATUS", "EXACT"),
                    cflags=kv.get("CFLAGS", ""),
                    toolchain=kv.get("TOOLCHAIN", ""),
                    marker_type="LIBRARY",
                    filepath=filepath.name,
                    source=kv.get("SOURCE", ""),
                    blocker=kv.get("BLOCKER", ""),
                    note=kv.get("NOTE", ""),
                )
            )

        i += 1

    return results


def remove_annotation_key(
    filepath: Path, va: int, key: str, metadata_dir: Path | None = None
) -> bool:
    """Remove an annotation key for a specific VA.

    For metadata-owned keys the matching field is deleted from ``rebrew-function.toml``.
    For non-metadata keys the existing in-file removal logic applies.

    Args:
        filepath: Path to the ``.c`` source file.
        va: Virtual address integer.
        key: Annotation key to remove.
        metadata_dir: Directory containing ``rebrew-function.toml``.
            Required for metadata-owned keys.

    Returns True if any change was made, False otherwise.

    """
    from rebrew.metadata import is_metadata_key, remove_field

    if is_metadata_key(key):
        module = module_for_va(filepath, va)
        _dir = metadata_dir if metadata_dir is not None else filepath.parent
        # Propagate remove_field's result: removing an absent key is a no-op
        # (False), not a claimed write.
        return remove_field(_dir, va, key.lower(), module=module)
    try:
        text, encoding = read_source_text(filepath)
    except OSError as e:
        warnings.warn(f"Cannot read {filepath} for annotation removal: {e}", stacklevel=2)
        return False

    return _strip_key_lines(filepath, va, key, text, encoding=encoding)


def _strip_key_lines(filepath: Path, va: int, key: str, text: str, encoding: str = "utf-8") -> bool:
    """Drop every ``// KEY:`` line inside the marker block for *va* and rewrite the file.

    *encoding* is the source file's detected encoding (see
    :func:`rebrew.utils.read_source_text`) and is preserved on write-back.

    Returns True if a line was removed.
    """
    in_target_block = False
    modified = False
    _key_pattern = _compile_key_pattern(key)

    new_lines = []
    for line in text.splitlines(keepends=True):
        marker_match = _MARKER_BLOCK_RE.search(line)
        if marker_match:
            found_va = int(marker_match.group(2), 16)
            # If we're in the target block and hit a different VA, we've crossed
            # into a sibling block — stop removal.  Otherwise match on VA.
            if in_target_block and found_va != va:  # noqa: SIM108
                in_target_block = False
            else:
                in_target_block = found_va == va

        if in_target_block and _key_pattern.search(line):
            modified = True
            continue  # Skip this line

        new_lines.append(line)

    if modified:
        atomic_write_text(filepath, "".join(new_lines), encoding=encoding)
    return modified


def remove_inline_annotation_key(filepath: Path, va: int, key: str) -> bool:
    """Remove an inline ``// KEY:`` comment from the source file only.

    Unlike :func:`remove_annotation_key`, this never touches
    ``rebrew-function.toml`` — the caller is responsible for metadata.
    Used by ``rebrew lint --fix`` to strip deprecated inline metadata keys
    after they have been migrated (removing them via the metadata-routing
    path would either delete the freshly written field or, for STATUS,
    raise).
    """
    try:
        text, encoding = read_source_text(filepath)
    except OSError:
        return False

    return _strip_key_lines(filepath, va, key, text, encoding=encoding)
