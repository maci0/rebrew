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
   ``/* name @ 0xVA (NB) - /flags - STATUS [ORIGIN] */``

The parser always tries the new format first; the old format is a fallback.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rebrew.utils import atomic_write_text

# ---------------------------------------------------------------------------
# Valid sets
# ---------------------------------------------------------------------------

VALID_MARKERS = {"FUNCTION", "LIBRARY", "STUB", "GLOBAL", "DATA"}
VALID_STATUSES = {"EXACT", "RELOC", "MATCHING", "MATCHING_RELOC", "STUB", "PROVEN"}
# Default origins — used as fallback when config is not available.
# Projects should define their own origins in rebrew-project.toml.
DEFAULT_ORIGINS = {"GAME", "MSVCRT", "ZLIB"}

REQUIRED_KEYS = {"STATUS", "ORIGIN", "SIZE", "CFLAGS"}
RECOMMENDED_KEYS = {"SYMBOL"}
OPTIONAL_KEYS = {
    "SOURCE",
    "BLOCKER",
    "BLOCKER_DELTA",
    "NOTE",
    "GLOBALS",
    "SKIP",
    "SECTION",
    "GHIDRA",
}
ALL_KNOWN_KEYS = REQUIRED_KEYS | RECOMMENDED_KEYS | OPTIONAL_KEYS | {"MARKER", "VA"}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Old format regex — matches the one-liner:
#   /* name @ 0xVA (NB) - /cflags - STATUS [ORIGIN] */
# Named groups:
#   name   — function name (e.g. "bit_reverse")
#   va     — virtual address hex (e.g. "0x10008880")
#   size   — size in bytes (e.g. "31")
#   cflags — compiler flags (e.g. "/O2 /Gd")
#   status — status string (e.g. "MATCHED")
#   origin — origin tag (e.g. "GAME")
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
    r"\s*\[(?P<origin>[A-Z]+)\]"
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
    """
    lines = text.splitlines(keepends=True)
    marker_indexes: list[int] = []
    for idx, line in enumerate(lines):
        if NEW_FUNC_CAPTURE_RE.match(line.strip()):
            marker_indexes.append(idx)

    if not marker_indexes:
        return text, []

    preamble = "".join(lines[: marker_indexes[0]])
    blocks: list[str] = []
    for i, start in enumerate(marker_indexes):
        end = marker_indexes[i + 1] if i + 1 < len(marker_indexes) else len(lines)
        blocks.append("".join(lines[start:end]))

    return preamble, blocks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalize_status(raw: str) -> str:
    """Map old-format status strings to canonical values.

    Check order matters: ``MATCHING_RELOC`` must be tested before both
    ``MATCHING`` and ``RELOC`` because it contains both as substrings.
    """
    s = raw.strip().upper()
    if "EXACT" in s:
        return "EXACT"
    # MATCHING_RELOC must precede MATCHING and RELOC (substring containment)
    if "MATCHING_RELOC" in s:
        return "MATCHING_RELOC"
    if "MATCHING" in s:
        return "MATCHING"
    if "RELOC" in s:
        return "RELOC"
    if "STUB" in s:
        return "STUB"
    return s


def normalize_cflags(raw: str) -> str:
    """Clean up cflags string."""
    return raw.strip().rstrip(",").strip()


def marker_for_origin(origin: str, status: str, library_origins: set[str] | None = None) -> str:
    """Derive expected marker type from origin and status.

    Args:
        origin: Origin tag (e.g. "GAME", "ZLIB").
        status: Status string (e.g. "EXACT", "STUB").
        library_origins: Set of origins that should use LIBRARY marker.
                         Defaults to {"ZLIB", "MSVCRT"} if not provided.
    """
    if status == "STUB":
        return "STUB"
    if library_origins is None:
        library_origins = {"ZLIB", "MSVCRT"}
    if origin in library_origins:
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
_FIELD_ALIASES = {"globals": "globals_list"}


@dataclass
class Annotation:
    """Parsed function annotation from a decomp .c file.

    Supports dict-like access (``ann["va"]``, ``ann["status"] = "EXACT"``)
    for backward compatibility with code that operated on raw dicts.
    """

    va: int = 0
    size: int = 0
    name: str = ""
    symbol: str = ""
    module: str = ""
    status: str = ""
    origin: str = ""
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

    # -- Dict-like access for backward compat --

    def __getitem__(self, key: str) -> Any:
        attr = _FIELD_ALIASES.get(key, key)
        try:
            return getattr(self, attr)
        except AttributeError:
            raise KeyError(key)

    def __setitem__(self, key: str, value: Any) -> None:
        attr = _FIELD_ALIASES.get(key, key)
        if hasattr(self, attr):
            object.__setattr__(self, attr, value)
        else:
            raise KeyError(key)

    def __contains__(self, key: str) -> bool:
        attr = _FIELD_ALIASES.get(key, key)
        return hasattr(self, attr)

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
            "origin": self.origin,
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
        }
        if self.section:
            d["section"] = self.section
        return d

    def validate(
        self,
        filepath: Path | None = None,
        valid_origins: set[str] | None = None,
        library_origins: set[str] | None = None,
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

        if self.origin and self.origin not in (valid_origins or DEFAULT_ORIGINS):
            errors.append(f"Invalid ORIGIN: {self.origin}")

        if self.size <= 0:
            errors.append(f"Invalid SIZE: {self.size}")

        # DATA annotations don't require CFLAGS (they aren't compiled)
        is_data = self.marker_type in ("DATA", "GLOBAL")
        if not is_data:
            if not self.cflags or not self.cflags.strip():
                errors.append("Missing CFLAGS")
            else:
                # Validate CFLAGS look like MSVC-style flags
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

        if not self.symbol:
            warnings.append("Missing SYMBOL (recommended)")

        _lib = library_origins if library_origins is not None else {"ZLIB", "MSVCRT"}
        expected_marker = marker_for_origin(self.origin, self.status, _lib)
        if self.marker_type and self.marker_type != expected_marker:
            warnings.append(
                f"Marker {self.marker_type} inconsistent with ORIGIN {self.origin} "
                f"(expected {expected_marker})"
            )

        if self.status == "STUB" and not self.blocker:
            warnings.append("STUB function missing BLOCKER annotation")

        if self.origin in _lib and not self.source:
            warnings.append(
                f"{self.origin} function missing SOURCE annotation "
                "(reference file, e.g. SBHEAP.C:195 or deflate.c)"
            )

        if self.status in ("MATCHING", "MATCHING_RELOC") and self.marker_type == "STUB":
            warnings.append(f"Contradictory: status is {self.status} but marker is STUB")

        if filepath and self.symbol:
            expected_stem = self.symbol.lstrip("_")
            if expected_stem and filepath.stem != expected_stem:
                warnings.append(
                    f"Filename '{filepath.name}' doesn't match SYMBOL "
                    f"'{self.symbol}' (expected '{expected_stem}{filepath.suffix}')"
                )

        return errors, warnings


def make_func_entry(
    va: int,
    size: int,
    name: str,
    symbol: str,
    status: str,
    origin: str,
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
    """Create an Annotation instance (backward-compat wrapper)."""
    return Annotation(
        va=va,
        size=size,
        name=name,
        symbol=symbol,
        module=module,
        status=status,
        origin=origin,
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


def update_size_annotation(filepath: Path, new_size: int) -> bool:
    """Update the ``// SIZE: NNN`` annotation in a .c file.

    Only increases size (safety: never shrinks a manually-set value).
    Returns True if the file was modified, False otherwise.
    """
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    size_re = re.compile(r"(//\s*SIZE:\s*)(\d+)")
    match = size_re.search(text)
    if not match:
        return False

    old_size = int(match.group(2))
    if new_size <= old_size:
        return False

    new_text = text[: match.start()] + match.group(1) + str(new_size) + text[match.end() :]
    atomic_write_text(filepath, new_text, encoding="utf-8")
    return True


def parse_old_format(line: str) -> Annotation | None:
    """Try to parse old-format header comment.  Returns Annotation or None."""
    m = OLD_RE.match(line.strip())
    if not m:
        return None
    status = normalize_status(m.group("status"))
    origin = m.group("origin").strip().upper()
    cflags = normalize_cflags(m.group("cflags"))
    name = m.group("name")
    module = m.groupdict().get("module", "") or ""

    mt = marker_for_origin(origin, status)

    return make_func_entry(
        va=int(m.group("va"), 16),
        size=int(m.group("size")),
        name=name,
        symbol="_" + name,
        module=module,
        status=status,
        origin=origin,
        cflags=cflags,
        marker_type=mt,
        filepath="",
    )


def _kv_to_annotation(
    kv: dict[str, str],
    marker_type: str,
    va: int,
    module: str,
) -> Annotation:
    """Convert a parsed key-value dict into an Annotation instance."""
    symbol = kv.get("SYMBOL", "")
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
        name=symbol.lstrip("_") if symbol else "",
        symbol=symbol,
        module=module,
        status=kv.get("STATUS", "RELOC"),
        origin=kv.get("ORIGIN", "GAME"),
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
    ann.prototype = kv.get("PROTOTYPE", "")
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

        if not in_annotation_block:
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
    entry = parse_new_format(lines[:20])
    if entry is not None:
        if target_name and entry.module and entry.module.lower() != target_name.lower():
            return None
        entry["filepath"] = rel
        return entry

    # Fallback: try old format (first line only)
    entry = parse_old_format(lines[0])
    if entry is not None:
        if target_name and entry.module and entry.module.lower() != target_name.lower():
            return None
        entry["filepath"] = rel
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

    def _flush() -> None:
        nonlocal current_marker_type, current_va, current_module, current_kv, pending_kv
        if current_marker_type is None or current_va is None:
            return
        results.append(
            _kv_to_annotation(current_kv, current_marker_type, current_va, current_module)
        )
        pending_kv = {}

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Check for a new marker line (starts a new block)
        m = NEW_FUNC_CAPTURE_RE.match(stripped) or BLOCK_FUNC_CAPTURE_RE.match(stripped)
        if m and m.group("type") in ("FUNCTION", "LIBRARY", "STUB"):
            # Save pending KV before flush (flush clears pending_kv)
            saved_pending = dict(pending_kv)
            # Flush the previous block before starting a new one
            _flush()
            current_marker_type = m.group("type")
            current_va = int(m.group("va"), 16)
            current_module = m.group("module")
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

        # Non-annotation line — DON'T break scanning (code between blocks)
        # Just skip it and keep looking for the next marker
        if current_marker_type is not None:
            seen_code_after_marker = True
        # Discard any orphaned pending KV (they belonged to no marker)
        pending_kv = {}

    # Flush the last block
    _flush()
    return results


def parse_c_file_multi(
    filepath: Path,
    target_name: str | None = None,
    base_dir: Path | None = None,
) -> list[Annotation]:
    """Parse ALL annotation blocks from a decomp .c file.

    Returns a list of Annotations, one per ``// FUNCTION:`` marker found
    in the file.  For single-function files this returns a one-element list.
    Returns an empty list if no annotations are found.

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
        return filtered_entries

    # Fallback: try old format (first line only) — returns at most one
    entry = parse_old_format(lines[0])
    if entry is not None:
        if target_name and entry.module and entry.module.lower() != target_name.lower():
            return []
        entry.filepath = rel
        return [entry]

    return []


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------


def parse_source_metadata(source_path: str | Path) -> dict[str, str]:
    """Extract annotation metadata as a flat dict.

    Delegates to the canonical ``parse_c_file`` parser so that every tool
    agrees on what the annotations say, then reshapes the result into the
    ``{KEY: value}`` dict format that callers expect. Marker entries map to
    the VA string only (for example ``{"FUNCTION": "0x10001a60"}``).
    """
    anno = parse_c_file(Path(source_path))
    if anno is None:
        return {}

    meta: dict[str, str] = {}
    # Map Annotation fields → the uppercase keys callers look up
    if anno.marker_type:
        # e.g. meta["FUNCTION"] = "SERVER 0x10001a60"
        va_hex = f"0x{anno.va:08x}" if anno.va is not None else ""
        meta[anno.marker_type] = va_hex
    if anno.status:
        meta["STATUS"] = anno.status
    if anno.origin:
        meta["ORIGIN"] = anno.origin
    if anno.size > 0:
        meta["SIZE"] = str(anno.size)
    if anno.cflags:
        meta["CFLAGS"] = anno.cflags
    if anno.symbol:
        meta["SYMBOL"] = anno.symbol
    if anno.blocker:
        meta["BLOCKER"] = anno.blocker
    if anno.source:
        meta["SOURCE"] = anno.source
    if anno.note:
        meta["NOTE"] = anno.note
    if anno.ghidra:
        meta["GHIDRA"] = anno.ghidra
    if anno.prototype:
        meta["PROTOTYPE"] = anno.prototype
    if anno.struct:
        meta["STRUCT"] = anno.struct
    if anno.callers:
        meta["CALLERS"] = anno.callers
    return meta


def update_annotation_key(filepath: Path, va: int, key: str, new_value: str) -> bool:
    """Update or add an annotation key like ``// SYMBOL: <value>`` for a specific VA.

    Returns True if the file was modified, False otherwise.
    """
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    lines = text.splitlines(keepends=True)
    in_target_block = False
    last_annotation_idx = -1
    modified = False
    escaped_key = re.escape(key)

    for i, line in enumerate(lines):
        # Check for marker: // FUNCTION: GAME 0x1000 or STUB or DATA etc.
        marker_match = re.search(
            r"(?://|/\*)\s*(FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*[A-Z0-9_]+\s+(0x[0-9a-fA-F]+)",
            line,
        )
        if marker_match:
            found_va = int(marker_match.group(2), 16)
            in_target_block = found_va == va

        if in_target_block:
            if line.strip().startswith("//") or line.strip().startswith("/*"):
                last_annotation_idx = i

            sym_match = re.search(
                r"((?://|/\*)\s*" + escaped_key + r":\s*)(.*?)(?=\s*(?:\*/|\n|$))", line
            )
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


def remove_annotation_key(filepath: Path, va: int, key: str) -> bool:
    """Remove an annotation key like ``// BLOCKER: <value>`` for a specific VA.

    Returns True if the file was modified, False otherwise.
    """
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    lines = text.splitlines(keepends=True)
    in_target_block = False
    modified = False
    escaped_key = re.escape(key)

    new_lines = []
    for line in lines:
        marker_match = re.search(
            r"(?://|/\*)\s*(FUNCTION|STUB|LIBRARY|DATA|GLOBAL):\s*[A-Z0-9_]+\s+(0x[0-9a-fA-F]+)",
            line,
        )
        if marker_match:
            found_va = int(marker_match.group(2), 16)
            in_target_block = found_va == va

        if in_target_block:
            sym_match = re.search(
                r"((?://|/\*)\s*" + escaped_key + r":\s*)(.*?)(?=\s*(?:\*/|\n|$))", line
            )
            if sym_match:
                modified = True
                continue  # Skip this line

        new_lines.append(line)

    if modified:
        atomic_write_text(filepath, "".join(new_lines), encoding="utf-8")
        return True

    return False
