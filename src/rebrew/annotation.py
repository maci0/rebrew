"""annotation.py - Shared annotation parsing for rebrew.

Extracts the common annotation-parsing logic used by both lint.py and verify.py
so that there is a single source of truth for the decomp annotation format.

Supports two formats:
  - **New (reccmp-style)**: ``// FUNCTION: SERVER 0x10008880`` followed by
    key-value lines like ``// STATUS: EXACT``.
  - **Old (legacy)**:  ``/* name @ 0xVA (NB) - /flags - STATUS [ORIGIN] */``
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Valid sets
# ---------------------------------------------------------------------------

VALID_MARKERS = {"FUNCTION", "LIBRARY", "STUB"}
VALID_STATUSES = {"EXACT", "RELOC", "MATCHING", "MATCHING_RELOC", "STUB"}
VALID_ORIGINS = {"GAME", "MSVCRT", "ZLIB"}

REQUIRED_KEYS = {"STATUS", "ORIGIN", "SIZE", "CFLAGS"}
RECOMMENDED_KEYS = {"SYMBOL"}
OPTIONAL_KEYS = {"SOURCE", "BLOCKER", "NOTE", "GLOBALS", "SKIP"}
ALL_KNOWN_KEYS = REQUIRED_KEYS | RECOMMENDED_KEYS | OPTIONAL_KEYS | {"MARKER", "VA"}

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

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

NEW_FUNC_RE = re.compile(r"//\s*(?:FUNCTION|LIBRARY|STUB):\s*\S+\s+0x[0-9a-fA-F]+")
NEW_FUNC_CAPTURE_RE = re.compile(
    r"//\s*(?P<type>FUNCTION|LIBRARY|STUB):\s*\S+\s+(?P<va>0x[0-9a-fA-F]+)"
)
NEW_KV_RE = re.compile(r"//\s*(?P<key>[A-Z]+):\s*(?P<value>.*)")

# Block-comment format: /* FUNCTION: SERVER 0x10003260 */
BLOCK_FUNC_RE = re.compile(
    r"/\*\s*(?:FUNCTION|LIBRARY|STUB):\s*\S+\s+0x[0-9a-fA-F]+\s*\*/"
)
BLOCK_FUNC_CAPTURE_RE = re.compile(
    r"/\*\s*(?P<type>FUNCTION|LIBRARY|STUB):\s*(?P<module>\S+)\s+(?P<va>0x[0-9a-fA-F]+)\s*\*/"
)
BLOCK_KV_RE = re.compile(r"/\*\s*(?P<key>[A-Z]+):\s*(?P<value>.*?)\s*\*/")

# Javadoc format: /** @address 0x10003640 ... */
JAVADOC_ADDR_RE = re.compile(r"@address\s+(?P<va>0x[0-9a-fA-F]+)")
JAVADOC_KV_RE = re.compile(r"@(?P<key>\w+)\s+(?P<value>.+)")

# Filename prefix → expected ORIGIN mapping
FILENAME_ORIGIN_PREFIXES = {
    "crt_": "MSVCRT",
    "zlib_": "ZLIB",
    "game_": "GAME",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def normalize_status(raw: str) -> str:
    """Map old-format status strings to canonical values."""
    s = raw.strip().upper()
    if "EXACT" in s:
        return "EXACT"
    if "RELOC" in s:
        return "RELOC"
    if "STUB" in s:
        return "STUB"
    return s


def normalize_cflags(raw: str) -> str:
    """Clean up cflags string."""
    return raw.strip().rstrip(",").strip()


def marker_for_origin(origin: str, status: str) -> str:
    """Derive expected marker type from origin and status."""
    if status == "STUB":
        return "STUB"
    if origin in ("ZLIB", "MSVCRT"):
        return "LIBRARY"
    return "FUNCTION"


def origin_from_filename(stem: str) -> str | None:
    """Guess expected ORIGIN from filename prefix."""
    for prefix, origin in FILENAME_ORIGIN_PREFIXES.items():
        if stem.startswith(prefix):
            return origin
    return None


# ---------------------------------------------------------------------------
# Data construction
# ---------------------------------------------------------------------------

# Field name mapping for dict-like access (handles "globals" → globals_list)
_FIELD_ALIASES = {"globals": "globals_list", "marker_type": "marker_type"}


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
    status: str = ""
    origin: str = ""
    cflags: str = ""
    marker_type: str = ""
    filepath: str = ""
    source: str = ""
    blocker: str = ""
    note: str = ""
    inline_error: str = ""
    globals_list: list[str] = field(default_factory=list)

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
        try:
            return self[key]
        except KeyError:
            return default

    def to_dict(self) -> dict:
        """Serialize to a plain dict (for JSON output or legacy code)."""
        return {
            "va": self.va,
            "size": self.size,
            "name": self.name,
            "symbol": self.symbol,
            "status": self.status,
            "origin": self.origin,
            "cflags": self.cflags,
            "marker_type": self.marker_type,
            "filepath": self.filepath,
            "source": self.source,
            "blocker": self.blocker,
            "note": self.note,
            "globals": self.globals_list,
        }

    def validate(self, filepath: Path | None = None) -> tuple[list[str], list[str]]:
        """Validate annotation fields. Returns (errors, warnings)."""
        errors: list[str] = []
        warnings: list[str] = []

        if self.marker_type and self.marker_type not in VALID_MARKERS:
            errors.append(f"Invalid marker type: {self.marker_type}")

        if self.inline_error:
            errors.append(f"Multiple annotations found on the same line: '{self.inline_error}' (please separate them into different lines)")

        if not (0x1000 <= self.va <= 0xFFFFFFFF):
            errors.append(f"VA 0x{self.va:x} is suspicious (outside 32-bit range)")

        if self.status and self.status not in VALID_STATUSES:
            errors.append(f"Invalid STATUS: {self.status}")

        if self.origin and self.origin not in VALID_ORIGINS:
            errors.append(f"Invalid ORIGIN: {self.origin}")

        if self.size <= 0:
            errors.append(f"Invalid SIZE: {self.size}")

        if not self.cflags:
            errors.append("Missing CFLAGS")

        if not self.symbol:
            warnings.append("Missing SYMBOL (recommended)")

        expected_marker = marker_for_origin(self.origin, self.status)
        if self.marker_type and self.marker_type != expected_marker:
            warnings.append(
                f"Marker {self.marker_type} inconsistent with ORIGIN {self.origin} "
                f"(expected {expected_marker})"
            )

        if self.status == "STUB" and not self.blocker:
            warnings.append("STUB function missing BLOCKER annotation")

        if self.origin in ("MSVCRT", "ZLIB") and not self.source:
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
                    f"'{self.symbol}' (expected '{expected_stem}.c')"
                )

        if filepath:
            expected_origin = origin_from_filename(filepath.stem)
            if expected_origin and self.origin and expected_origin != self.origin:
                warnings.append(
                    f"Filename prefix suggests ORIGIN '{expected_origin}' "
                    f"but annotation says '{self.origin}'"
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


def parse_old_format(line: str) -> Annotation | None:
    """Try to parse old-format header comment.  Returns Annotation or None."""
    m = OLD_RE.match(line.strip())
    if not m:
        return None
    status = normalize_status(m.group("status"))
    origin = m.group("origin").strip().upper()
    cflags = normalize_cflags(m.group("cflags"))
    name = m.group("name")

    mt = marker_for_origin(origin, status)

    return make_func_entry(
        va=int(m.group("va"), 16),
        size=int(m.group("size")),
        name=name,
        symbol="_" + name,
        status=status,
        origin=origin,
        cflags=cflags,
        marker_type=mt,
        filepath="",
    )


def parse_new_format(lines: list[str]) -> Annotation | None:
    """Try to parse new reccmp-style annotations from first lines.
    Returns Annotation or None."""
    marker_type = None
    va = None
    kv: dict[str, str] = {}

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
            
        # Check for multiple annotations on one line
        if stripped.count("//") > 1:
            # We strictly enforce one annotation per line
            # We will grab the first one so at least it parses something,
            # but the linter will complain later (we will add a check in validate).
            pass
            
        # Check for marker
        m = NEW_FUNC_CAPTURE_RE.match(stripped) or BLOCK_FUNC_CAPTURE_RE.match(stripped)
        if m:
            marker_type = m.group("type")
            va = int(m.group("va"), 16)
            
            # If there's inline stuff after the VA, stash it in a special internal field to lint later
            if stripped.count("//") > 1:
                kv["_INLINE_ERROR"] = stripped
            continue
            
        # Check for key-value
        m2 = NEW_KV_RE.match(stripped) or BLOCK_KV_RE.match(stripped)
        if m2:
            key = m2.group("key").upper()
            val = m2.group("value").strip()
            
            # Stash the full line if there are multiple slashes
            if stripped.count("//") > 1:
                kv["_INLINE_ERROR"] = stripped
                
                # Try to extract just the first value before the next //
                if "//" in val:
                    val = val.split("//")[0].strip()
                    
            kv[key] = val
            continue
            
        # Non-annotation line => stop
        break

    if marker_type is None or va is None:
        return None

    status = kv.get("STATUS", "RELOC")
    origin = kv.get("ORIGIN", "GAME")
    size_str = kv.get("SIZE", "0")
    cflags = kv.get("CFLAGS", "")
    symbol = kv.get("SYMBOL", "")
    name = symbol.lstrip("_") if symbol else ""

    try:
        size = int(size_str)
    except ValueError:
        size = 0

    source = kv.get("SOURCE", "")
    blocker = kv.get("BLOCKER", "")
    note = kv.get("NOTE", "")

    globals_list: list[str] = []
    raw_globals = kv.get("GLOBALS", "")
    if raw_globals:
        globals_list = [g.strip() for g in raw_globals.split(",") if g.strip()]

    return make_func_entry(
        va=va,
        size=size,
        name=name,
        symbol=symbol,
        status=status,
        origin=origin,
        cflags=cflags,
        marker_type=marker_type,
        filepath="",
        source=source,
        blocker=blocker,
        note=note,
        inline_error=kv.get("_INLINE_ERROR", ""),
        globals_list=globals_list,
    )


def parse_c_file(filepath: Path) -> Annotation | None:
    """Parse a decomp .c file for annotations (tries new then old format)."""
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    lines = text.splitlines()
    if not lines:
        return None

    # Try new format first (multi-line)
    entry = parse_new_format(lines[:20])
    if entry is not None:
        entry["filepath"] = filepath.name
        return entry

    # Try old format (first line)
    entry = parse_old_format(lines[0])
    if entry is not None:
        entry["filepath"] = filepath.name
        return entry

    return None
