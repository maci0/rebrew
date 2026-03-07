"""annotation.py - Shared annotation parsing for rebrew.

Extracts the common annotation-parsing logic used by both lint.py and verify.py
so that there is a single source of truth for the decomp annotation format.

Supports three annotation formats:

1. **New (reccmp-style)** — the canonical format:
   ``// FUNCTION: SERVER 0x10008880`` followed by key-value lines
   like ``// STATUS: EXACT``.  This is what all tools output.

2. **Block-comment variant** — same semantics but wrapped in ``/* ... */``:
   ``/* FUNCTION: SERVER 0x10003260 */``

3. **Old (legacy)** — single-line shorthand from early decomp work:
   ``/* name @ 0xVA (NB) - /flags - STATUS */``

The parser always tries the new format first; the old format is a fallback.
"""

from __future__ import annotations

import contextlib
import logging
import re
import warnings
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Final

from rebrew.utils import atomic_write_text

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_PARSE_LOOKAHEAD_LINES: Final[int] = 20
"""Maximum lines scanned from file start when looking for a new-format annotation marker.

Keeping this small avoids large readaheads on files with deeply-nested preambles.
Increasing it would allow markers buried further down the file to be found by
``parse_c_file``; ``parse_c_file_multi`` already scans the full file instead.
"""

__all__ = [
    "Annotation",
    "VALID_MARKERS",
    "VALID_STATUSES",
    "has_skip_annotation",
    "parse_c_file",
    "parse_c_file_multi",
    "parse_source_metadata",
    "resolve_symbol",
    "update_annotation_key",
    "remove_annotation_key",
    "update_size_annotation",
]

# ---------------------------------------------------------------------------
# Valid sets
# ---------------------------------------------------------------------------

VALID_MARKERS = {"FUNCTION", "LIBRARY", "STUB", "GLOBAL", "DATA"}
VALID_STATUSES = {"EXACT", "RELOC", "MATCHING", "MATCHING_RELOC", "STUB", "PROVEN"}

# Keys that every function block must declare.
# CFLAGS is intentionally excluded: it falls back to the project-wide base_cflags.
# SIZE is intentionally excluded: it lives exclusively in the rebrew-functions.toml sidecar
# (written by rebrew skeleton / catalog --update-sizes / update_size_annotation). Any
# remaining // SIZE: lines in existing source are read as a parse-time fallback but the
# sidecar always wins via merge_into_annotation(); new files must NOT have // SIZE: at all.
REQUIRED_KEYS = {"STATUS"}
# No recommended keys — all annotation metadata is either required or optional.
RECOMMENDED_KEYS: set[str] = set()
OPTIONAL_KEYS = {
    # Volatile metadata (lives in rebrew-functions.toml sidecar, not in .c files)
    "CFLAGS",  # overrides project default; rare (library with different flags)
    # SIZE lives in the sidecar. Existing files may still contain // SIZE: as a
    # backward-compat fallback (parsed but never written by new code). Keeping it
    # here suppresses W010 "unknown key" warnings on those legacy annotations.
    "SIZE",
    # Other optional fields
    "ANALYSIS",
    "SOURCE",
    "BLOCKER",
    "BLOCKER_DELTA",
    "NOTE",
    "GLOBALS",
    "SKIP",
    "SECTION",
    "GHIDRA",
}
ALL_KNOWN_KEYS = REQUIRED_KEYS | OPTIONAL_KEYS | {"MARKER", "VA"}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Old format regex — matches the one-liner:
#   /* name @ 0xVA (NB) - /cflags - STATUS */
# Named groups:
#   name   — function name (e.g. "bit_reverse")
#   va     — virtual address hex (e.g. "0x10008880")
#   size   — size in bytes (e.g. "31")
#   cflags — compiler flags (e.g. "/O2 /Gd")
#   status — status string (e.g. "MATCHED")
OLD_RE = re.compile(
    r"/\*\s*"
    r"(?P<name>\S+)"
    r"\s+@\s+"
    r"(?P<va>0x[0-9a-fA-F]+)"
    r"\s+\((?P<size>\d+)B\)"
    r"\s*-\s*"
    r"(?P<cflags>[^-]+?)"
    r"\s*-\s*"
    r"(?P<status>[^[]+?)"
    r"(?:\s*\[[A-Z]+\])?"
    r"\s*\*/"
)

# New format — line-comment style (the canonical output format).
# Quick match (no captures): used to test if a line is a marker line.
NEW_FUNC_RE = re.compile(r"//\s*(?:FUNCTION|LIBRARY|STUB|GLOBAL|DATA):\s*\S+\s+0x[0-9a-fA-F]+")
# Full capture: extracts the marker type and VA.
NEW_FUNC_CAPTURE_RE = re.compile(
    r"//\s*(?P<type>FUNCTION|LIBRARY|STUB|GLOBAL|DATA):\s*(?P<module>\S+)\s+(?P<va>0x[0-9a-fA-F]+)"
)
# Key-value pairs: ``// STATUS: EXACT``, ``// SIZE: 31``, etc.
NEW_KV_RE = re.compile(r"//\s*(?P<key>[A-Z_]+):\s*(?P<value>.*)")

# Block-comment format — same semantics, different delimiters.
# Used by some auto-migrated files: /* FUNCTION: SERVER 0x10003260 */
BLOCK_FUNC_RE = re.compile(
    r"/\*\s*(?:FUNCTION|LIBRARY|STUB|GLOBAL|DATA):\s*\S+\s+0x[0-9a-fA-F]+\s*\*/"
)
BLOCK_FUNC_CAPTURE_RE = re.compile(
    r"/\*\s*(?P<type>FUNCTION|LIBRARY|STUB|GLOBAL|DATA):\s*(?P<module>\S+)\s+(?P<va>0x[0-9a-fA-F]+)\s*\*/"
)
BLOCK_KV_RE = re.compile(r"/\*\s*(?P<key>[A-Z_]+):\s*(?P<value>.*?)\s*\*/")

# Function name hint — bare ``// FunctionName`` comment after a marker line.
# Matches a single-word identifier (no colon, no spaces) that is not a KV key.
# Used to capture the actual function name in multi-function files where SYMBOL
# may be shared across blocks.
FUNC_NAME_HINT_RE = re.compile(r"^//\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*$")

# C function definition — extracts the function name and full prototype from a
# line like ``int __cdecl LoadGraveyardData(int param_1, int param_2)``.
# Captures everything before '(' to allow extracting name + full signature.
# Handles return types, calling conventions (__cdecl, __stdcall, __fastcall),
# declspecs, and macros.
_C_FUNC_IDENT_RE = re.compile(
    r"^\s*"  # leading whitespace
    r"(?!extern\b|typedef\b|__declspec\b)"  # NOT a forward declaration, typedef, or declspec
    r"(?:(?:static|inline|unsigned|signed|const|volatile|struct|enum|union|void|char|short|int|long|float|double|__int64|BOOL|DWORD|WORD|BYTE|LONG|UINT|ULONG|HRESULT)\s+)*"  # return type qualifiers
    r"(?:[A-Za-z_][A-Za-z0-9_*\s]*?\s+)?"  # return type (flexible)
    r"(?:(?:__cdecl|__stdcall|__fastcall|__thiscall|WINAPI|CALLBACK|APIENTRY|REBREW_NAKED)\s+)*"  # calling convention
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"  # function name
    r"\s*\(",  # opening paren
)

# Javadoc format — rare, from early experiments:
#   /** @address 0x10003640  @origin GAME */
JAVADOC_ADDR_RE = re.compile(r"@address\s+(?P<va>0x[0-9a-fA-F]+)")
JAVADOC_KV_RE = re.compile(r"@(?P<key>\w+)\s+(?P<value>.+)")

# ---------------------------------------------------------------------------
# Section splitting helper (shared by split.py and merge.py)
# ---------------------------------------------------------------------------


def split_annotation_sections(text: str) -> tuple[str, list[str]]:
    """Split annotated source into (preamble, function_blocks).

    Splits on ``// FUNCTION:`` (or LIBRARY/STUB/GLOBAL/DATA) marker lines,
    returning the text before the first marker as the preamble and each
    marker-delimited section as a block string.

    Annotation key-value lines (``// STATUS: EXACT``, ``// SIZE: 160``, etc.)
    immediately preceding a marker are included in that marker's block rather
    than the preamble, so that annotations stay with their function during
    merge/split operations.
    """
    lines = text.splitlines(keepends=True)
    marker_indexes: list[int] = []
    for idx, line in enumerate(lines):
        if NEW_FUNC_CAPTURE_RE.match(line.strip()):
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
            if NEW_KV_RE.match(prev_line) or BLOCK_KV_RE.match(prev_line):
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
            if stripped and (NEW_KV_RE.match(stripped) or BLOCK_KV_RE.match(stripped)):
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

    Check order matters: ``MATCHING_RELOC`` must be tested before both
    ``MATCHING`` and ``RELOC`` because it contains both as substrings.
    ``PROVEN`` is an independent canonical value — included before the
    generic fallthrough so old-format strings like ``"PROVEN_MATCH"``
    are normalised to ``"PROVEN"`` rather than returned verbatim.
    """
    s = raw.strip().upper()
    # MATCHING_RELOC must precede both MATCHING and RELOC (substring containment)
    if "MATCHING_RELOC" in s:
        return "MATCHING_RELOC"
    if "EXACT" in s:
        return "EXACT"
    if "MATCHING" in s:
        return "MATCHING"
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

    """
    if status == "STUB":
        return "STUB"
    if library_modules and module in library_modules:
        return "LIBRARY"
    return "FUNCTION"


def has_skip_annotation(filepath: Path) -> bool:
    """Check if a .c file has a ``// SKIP:`` annotation in the first 20 lines."""
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in text.splitlines()[:20]:
        stripped = line.strip().upper()
        if stripped.startswith(("// SKIP:", "/* SKIP:")):
            return True
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

    Supports dict-like access (``ann.va``, ``ann.status = "EXACT"``)
    for backward compatibility with code that operated on raw dicts.
    """

    va: int = 0
    size: int = 0
    name: str = ""
    symbol: str = ""
    module: str = ""
    status: str = ""
    cflags: str = ""
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

    # -- Dict-like access for backward compat --

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

    def __contains__(self, key: str) -> bool:
        """Return True if *key* (or its alias) is a field of this Annotation."""
        attr = _FIELD_ALIASES.get(key, key)
        return attr in {f.name for f in fields(self)}

    def get(self, key: str, default: Any = None) -> Any:
        """Return the value for *key*, or *default* if not present."""
        try:
            return self[key]
        except KeyError:
            return default

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (for JSON output or legacy code)."""
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
        return d

    def validate(
        self,
        filepath: Path | None = None,
        library_modules: set[str] | None = None,
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

        if self.va < 0x1000:
            errors.append(f"VA 0x{self.va:x} is suspicious (below 0x1000)")

        if self.status and self.status not in VALID_STATUSES:
            errors.append(f"Invalid STATUS: {self.status}")

        if self.size <= 0:
            errors.append(f"Invalid SIZE: {self.size}")

        # Validate CFLAGS format if present (not required — falls back to target default)
        if self.cflags.strip():
            flags = self.cflags.strip().split()
            for flag in flags:
                if not flag.startswith("/") and not flag.startswith("-"):
                    warnings.append(
                        f"CFLAGS token '{flag}' doesn't start with '/' or '-' "
                        "(expected MSVC-style flags like /O2 /Gd)"
                    )
            # Detect common typo: flags glued together like "/O2/Gd"
            for flag in flags:
                if re.match(r"^/\w+/\w+", flag):
                    warnings.append(
                        f"CFLAGS token '{flag}' looks like multiple flags "
                        "glued together (missing space?)"
                    )

        # Check marker consistency against module name
        _lib = library_modules or set()
        expected_marker = marker_for_module(self.module, self.status, _lib)
        if self.marker_type and self.marker_type != expected_marker:
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

        if self.status in ("MATCHING", "MATCHING_RELOC") and self.marker_type == "STUB":
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


def _module_for_va(filepath: Path, va: int) -> str:
    """Scan *filepath* for a marker line for *va* and return its module name.

    Returns the module name (e.g. ``"SERVER"``) or an empty string if not found.
    Used by annotation mutation helpers to route sidecar writes to the correct key.
    """
    _marker_re = re.compile(
        r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*([\w.]+)\s+(0x[0-9a-fA-F]+)",
        re.IGNORECASE,
    )
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    for line in text.splitlines():
        m = _marker_re.search(line)
        if m and int(m.group(2), 16) == va:
            return m.group(1)
    return ""


def update_size_annotation(filepath: Path, new_size: int, target_va: int | None = None) -> bool:
    """Update the SIZE for a function — always writes to the sidecar.

    Writes *new_size* to the ``rebrew-functions.toml`` sidecar in the same
    directory as *filepath* (only increasing, never shrinking).

    *target_va* is required for multi-function files; for single-function files
    it can be omitted and will be inferred from the marker line.

    Returns True if any change was made, False otherwise.

    Args:
        filepath: Path to the .c source file (used to locate the directory).
        new_size: New SIZE value.
        target_va: VA of the specific function to update.  Required for files
            with multiple FUNCTION: markers; otherwise inferred automatically.

    """
    from rebrew.sidecar import get_entry, set_field

    # Resolve VA if not provided — scan file for the first marker line
    va = target_va
    if va is None:
        marker_re = re.compile(
            r"(?://|/\*)\s*(?:FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*\S+\s+(0x[0-9a-fA-F]+)"
        )
        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            warnings.warn(f"Cannot read {filepath} for size update: {e}", stacklevel=2)
            return False
        for line in text.splitlines():
            m = marker_re.search(line)
            if m:
                va = int(m.group(1), 16)
                break

    if va is None:
        return False

    module = _module_for_va(filepath, va)
    entry = get_entry(filepath.parent, va, module=module)
    old_size = int(entry.get("size", 0))
    if new_size <= old_size:
        return False
    set_field(filepath.parent, va, "size", new_size, module=module)
    return True


def parse_old_format(line: str) -> Annotation | None:
    """Try to parse old-format header comment.  Returns Annotation or None."""
    m = OLD_RE.match(line.strip())
    if not m:
        return None
    status = normalize_status(m.group("status"))
    cflags = normalize_cflags(m.group("cflags"))
    name = m.group("name")
    module = ""  # OLD_RE has no module group; always empty for legacy format

    mt = "STUB" if status == "STUB" else "FUNCTION"

    ann = make_func_entry(
        va=int(m.group("va"), 16),
        size=int(m.group("size")),
        name=name,
        symbol="_" + name,
        module=module,
        status=status,
        cflags=cflags,
        marker_type=mt,
        filepath="",
    )
    ann.line = 1  # old-format annotations are always on the first line
    return ann


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
    # Extract the parameter list between parens
    paren_start = proto.find("(")
    paren_end = proto.rfind(")")
    if paren_start < 0 or paren_end < 0 or paren_end <= paren_start:
        return None

    params_str = proto[paren_start + 1 : paren_end].strip()

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
        params_str = re.sub(r"<[^<>]*>", "", params_str)

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

    Symbol is always derived as ``"_" + name`` (standard __cdecl convention).
    Prototype is extracted from the actual C function definition line when
    available.

    ``// SYMBOL:`` and ``// PROTOTYPE:`` annotations are no longer supported;
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

    # Derive symbol: "_" + name for __cdecl (default), "_" + name + "@N" for __stdcall/WINAPI
    symbol = "_" + name if name else ""
    if name and c_func_proto:
        _stdcall_re = re.compile(r"\b(?:__stdcall|WINAPI|CALLBACK|APIENTRY)\b")
        if _stdcall_re.search(c_func_proto):
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
        status=kv.get("STATUS", "RELOC"),
        cflags=kv.get("CFLAGS", ""),
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

    State machine: scans up to 20 lines looking for a marker line
    (``// FUNCTION: SERVER 0x...``), then collects subsequent key-value
    comment lines until a non-annotation line is hit. Non-annotation
    preamble lines before the marker are tolerated. Returns None if
    no valid marker line is found.
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

        # Check for marker
        m = NEW_FUNC_CAPTURE_RE.match(stripped) or BLOCK_FUNC_CAPTURE_RE.match(stripped)
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
        m2 = NEW_KV_RE.match(stripped) or BLOCK_KV_RE.match(stripped)
        if m2:
            key = m2.group("key").upper()
            val = m2.group("value").strip()
            kv[key] = val
            continue

        # Check for function name hint: bare "// FunctionName" after marker
        if in_annotation_block and "_FUNC_NAME_HINT" not in kv:
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
        if "_C_FUNC_NAME" not in kv:
            m4 = _C_FUNC_IDENT_RE.match(stripped)
            if m4 and not stripped.rstrip().endswith(";"):
                kv["_C_FUNC_NAME"] = m4.group("name")
                # Extract full prototype: everything up to the closing paren
                proto_line = stripped.rstrip("{;").strip()
                kv["_C_FUNC_PROTO"] = proto_line
            elif m4:
                # Forward declaration — skip it, keep looking
                continue

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

    Format disambiguation: tries the new (multi-line ``// KEY: value``)
    format first against the first 20 lines, then falls back to the
    old single-line legacy format on line 1 only.

    Sets ``filepath`` on the returned Annotation for downstream use.
    When *base_dir* is given the stored path is relative to it (e.g.
    ``"zlib/zlib_adler32.c"``); otherwise only the bare filename is kept.
    """
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    lines = text.splitlines()
    if not lines:
        return None

    rel = _relative_filepath(filepath, base_dir)

    # Try new format first (multi-line) — preferred, canonical output
    entry = parse_new_format(lines[:_PARSE_LOOKAHEAD_LINES])
    if entry is not None:
        if target_name and entry.module and entry.module.lower() != target_name.lower():
            return None
        entry.filepath = rel
        return entry

    # Fallback: try old format (first line only)
    entry = parse_old_format(lines[0])
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

        # Check for a new marker line (starts a new block)
        m = NEW_FUNC_CAPTURE_RE.match(stripped) or BLOCK_FUNC_CAPTURE_RE.match(stripped)
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
        m2 = NEW_KV_RE.match(stripped) or BLOCK_KV_RE.match(stripped)
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
        if current_marker_type is not None and not seen_code_after_marker:
            m3 = FUNC_NAME_HINT_RE.match(stripped)
            if m3 and "_FUNC_NAME_HINT" not in current_kv:
                current_kv["_FUNC_NAME_HINT"] = m3.group("name")
                continue

        # Try to extract function name from C definition line.
        # Skip forward declarations (lines ending with ';') — only match
        # actual function definitions.
        if current_marker_type is not None and "_C_FUNC_NAME" not in current_kv:
            m4 = _C_FUNC_IDENT_RE.match(stripped)
            if m4 and not stripped.rstrip().endswith(";"):
                current_kv["_C_FUNC_NAME"] = m4.group("name")
                proto_line = stripped.rstrip("{;").strip()
                current_kv["_C_FUNC_PROTO"] = proto_line

        # Non-annotation line — DON'T break scanning (code between blocks)
        # Just skip it and keep looking for the next marker
        if current_marker_type is not None:
            seen_code_after_marker = True
        # Keep pending_kv intact — annotations before code (like STATUS,
        # ORIGIN, SIZE at the top of a file) need to survive through
        # #include, extern, and typedef lines to reach the FUNCTION marker.

    # Flush the last block
    _flush()
    if pending_kv:
        logger.debug("Discarding orphaned KV annotations: %s", pending_kv)
    return results


def parse_c_file_multi(
    filepath: Path,
    target_name: str | None = None,
    base_dir: Path | None = None,
    sidecar_dir: Path | None = None,
) -> list[Annotation]:
    """Parse ALL annotation blocks from a decomp .c file.

    Returns a list of Annotations, one per ``// FUNCTION:`` marker found
    in the file.  For single-function files this returns a one-element list.
    Returns an empty list if no annotations are found.

    When *sidecar_dir* is provided each returned Annotation is overlaid with
    values from that directory's ``rebrew-functions.toml`` (sidecar wins for volatile
    fields like STATUS, SIZE, CFLAGS, BLOCKER, NOTE, GHIDRA).  Pass
    ``filepath.parent`` as *sidecar_dir* to enable sidecar merging for a
    single-file call.

    Sets ``filepath`` on each returned Annotation.  When *base_dir* is
    given the stored path is relative to it; otherwise the bare filename.
    """
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    lines = text.splitlines()
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
        if sidecar_dir is not None:
            from rebrew.sidecar import merge_into_annotation

            for entry in filtered_entries:
                merge_into_annotation(entry, sidecar_dir)
        return filtered_entries

    # Fallback: try old format (first line only) — returns at most one
    fallback_entry = parse_old_format(lines[0])
    if fallback_entry is not None:
        if (
            target_name
            and fallback_entry.module
            and fallback_entry.module.lower() != target_name.lower()
        ):
            return []
        fallback_entry.filepath = rel
        if sidecar_dir is not None:
            from rebrew.sidecar import merge_into_annotation

            merge_into_annotation(fallback_entry, sidecar_dir)
        return [fallback_entry]

    return []


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------


def parse_source_metadata(source_path: str | Path) -> dict[str, str]:
    """Extract annotation metadata as a flat dict.

    Delegates to the canonical ``parse_c_file_multi`` parser so that every tool
    agrees on what the annotations say, then reshapes the result into the
    ``{KEY: value}`` dict format that callers expect. Marker entries map to
    the VA string only (for example ``{"FUNCTION": "0x10001a60"}``).
    """
    annos = parse_c_file_multi(Path(source_path), sidecar_dir=Path(source_path).parent)
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
    # SYMBOL is derived from function name — don't emit as annotation
    # if anno.symbol:
    #     meta["SYMBOL"] = anno.symbol
    if anno.blocker:
        meta["BLOCKER"] = anno.blocker
    if anno.source:
        meta["SOURCE"] = anno.source
    if anno.note:
        meta["NOTE"] = anno.note
    if anno.ghidra:
        meta["GHIDRA"] = anno.ghidra
    # PROTOTYPE is derived from C definition — don't emit as annotation
    # if anno.prototype:
    #     meta["PROTOTYPE"] = anno.prototype
    if anno.struct:
        meta["STRUCT"] = anno.struct
    if anno.callers:
        meta["CALLERS"] = anno.callers
    return meta


def update_annotation_key(filepath: Path, va: int, key: str, new_value: str) -> bool:
    """Update or add an annotation key for a specific VA.

    For sidecar-owned keys (STATUS, SIZE, CFLAGS, BLOCKER, NOTE, GHIDRA, …)
    the value is written to the ``rebrew-functions.toml`` sidecar in the same directory
    as *filepath*, leaving the ``.c`` file untouched.  For non-sidecar keys
    (ORIGIN, SOURCE for library functions) the existing in-file edit logic
    applies.

    Returns True if any write was made, False otherwise.
    """
    from rebrew.sidecar import is_sidecar_key, set_field

    if is_sidecar_key(key):
        module = _module_for_va(filepath, va)
        set_field(filepath.parent, va, key.lower(), new_value, module=module)
        return True
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        warnings.warn(f"Cannot read {filepath} for annotation update: {e}", stacklevel=2)
        return False

    lines = text.splitlines(keepends=True)
    in_target_block = False
    last_annotation_idx = -1
    modified = False
    escaped_key = re.escape(key)
    _marker_pattern = re.compile(
        r"(?://|/\*)\s*(FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*\S+\s+(0x[0-9a-fA-F]+)"
    )
    _key_pattern = re.compile(r"((?://|/\*)\s*" + escaped_key + r":\s*)(.*?)(?=\s*(?:\*/|\n|$))")

    for i, line in enumerate(lines):
        # Check for marker: // FUNCTION: GAME 0x1000 or STUB or DATA etc.
        marker_match = _marker_pattern.search(line)
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
        atomic_write_text(filepath, "".join(lines), encoding="utf-8")
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
        // STATUS: MATCHING
        // SIZE: 120
        // CFLAGS: /O2 /Gd
        // SOURCE: deflate.c

    reccmp's parser reads the marker + symbol, then moves on; the KV lines
    are invisible to it.  Rebrew captures them to support library functions
    that are actively compiled and matched from reference source.

    Returns a list of Annotations with marker_type=LIBRARY and origin
    inferred from the filename.  Entries without explicit STATUS default
    to EXACT.
    """
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
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

            # Apply target filter
            if target_name and module.lower() != target_name.lower():
                i += 1
                continue

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
                    marker_type="LIBRARY",
                    filepath=filepath.name,
                    source=kv.get("SOURCE", ""),
                    blocker=kv.get("BLOCKER", ""),
                    note=kv.get("NOTE", ""),
                )
            )

        i += 1

    return results


def remove_annotation_key(filepath: Path, va: int, key: str) -> bool:
    """Remove an annotation key for a specific VA.

    For sidecar-owned keys the matching field is deleted from ``rebrew-functions.toml``.
    For non-sidecar keys the existing in-file removal logic applies.

    Returns True if any change was made, False otherwise.
    """
    from rebrew.sidecar import delete_field, is_sidecar_key

    if is_sidecar_key(key):
        module = _module_for_va(filepath, va)
        delete_field(filepath.parent, va, key.lower(), module=module)
        return True
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        warnings.warn(f"Cannot read {filepath} for annotation removal: {e}", stacklevel=2)
        return False

    lines = text.splitlines(keepends=True)
    in_target_block = False
    modified = False
    escaped_key = re.escape(key)
    _marker_pattern = re.compile(
        r"(?://|/\*)\s*(FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*[A-Z0-9_]+\s+(0x[0-9a-fA-F]+)"
    )
    _key_pattern = re.compile(r"((?://|/\*)\s*" + escaped_key + r":\s*)(.*?)(?=\s*(?:\*/|\n|$))")

    new_lines = []
    for line in lines:
        marker_match = _marker_pattern.search(line)
        if marker_match:
            found_va = int(marker_match.group(2), 16)
            # Ternary: if we are already in the target block and the new VA is
            # different, we've crossed into a sibling block — stop removal there.
            # Otherwise set in_target_block based on whether this VA matches.
            in_target_block = False if in_target_block and found_va != va else found_va == va

        if in_target_block:
            sym_match = _key_pattern.search(line)
            if sym_match:
                modified = True
                continue  # Skip this line

        new_lines.append(line)

    if modified:
        atomic_write_text(filepath, "".join(new_lines), encoding="utf-8")
        return True

    return False
