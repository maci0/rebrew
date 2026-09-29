"""lint.py - Annotation linter for rebrew decomp C files.

Check that all .c files in the reversed directory have proper reccmp-style
annotations (``// FUNCTION: MODULE 0xVA`` markers) and that volatile metadata
(STATUS, BLOCKER, NOTE, …) lives in ``rebrew-functions.toml``. ``SIZE`` /
``CFLAGS`` are co-read (inline reccmp contract + TOML override; W019 warns on
disagreement, does not migrate). Also cross-checks FUNCTION/STUB marker VAs
against the target's function list (W028), flags redundant per-function /
preset cflags that only repeat an inherited value (W029), and otherwise
catches stale annotations at lint time instead of as confusing mismatches in
``rebrew test``.
Supports ``--fix`` to migrate inline metadata keys to the TOML metadata file
and to drop redundant per-function / preset cflags (W029).

Inspired by reccmp's decomplint tool.
"""

import bisect
import contextlib
import logging
import re
import threading
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.table import Table
from rich.text import Text

from rebrew.annotation import (
    ALL_KNOWN_KEYS,
    DATA_MARKERS,
    METADATA_KEYS,
    MIN_VALID_VA,
    NEW_FUNC_RE,
    NEW_KV_RE,
    VALID_MARKERS,
    min_valid_va_for,
)
from rebrew.cli import (
    EXIT_MISMATCH,
    AllTargetsOption,
    TargetOption,
    all_targets_run,
    console,
    error_exit,
    json_print,
    option_default,
)
from rebrew.config import (
    DEFAULT_LINT_MAX_LINE_LENGTH,
    ProjectConfig,
    inventory_path_for,
    load_config,
)
from rebrew.data_metadata import load_data_metadata
from rebrew.lint_cflags import (
    RedundantFunctionCflags,
    RedundantPreset,
    cflags_key,
    check_redundant_cflags,
    codegen_cflags_key,
    drop_redundant_presets,
    inline_equals_store,
)
from rebrew.metadata import (
    MARKER_IDENTITY_FIELDS,
    METADATA_FIELDS,
    canonical_status,
    is_table_field,
    load_metadata,
)
from rebrew.sources import (
    iter_sources,
    source_exts,
)
from rebrew.utils import (
    preset_module_key,
    read_source_text,
    rel_display_path,
    split_source_lines,
    untrusted_ident,
)
from rebrew.workspace.status import EARNED_STATUSES, KNOWN_STATUSES, MATCHED_STATUSES

log = logging.getLogger(__name__)

# Marker header line in either comment style.  annotation.NEW_FUNC_CAPTURE_RE
# accepts `//` and `/*` (the C89-strict form intake emits for borland-2.0/msvc-1.52), so
# lint must not report E001/E002 on a file the parser reads fine.
_HEADER_MARKER_RE = re.compile(r"(?://|/\*)\s*(\w+):\s*(\S+)\s+(0x[0-9a-fA-F]+)")
_SIZE_ANNOTATION_RE = re.compile(r"//\s*SIZE\s+0x[0-9a-fA-F]+")
# The two comment styles a marker header can wear (see _HEADER_MARKER_RE).
# A check that recognizes only `//` silently skips a whole `/*` marker block.
# Module is part of the identity: SERVER and GOLDTL may both annotate
# g_log_newline. Two files annotating one name for the same module still warn.
_DATA_MARKER_RE = re.compile(r"(?://|/\*)\s*(DATA|GLOBAL):\s*([A-Za-z_][A-Za-z0-9_]*)")


def _is_comment_line(text: str) -> bool:
    """True when *text* is a whole-line comment in either supported style."""
    stripped = text.lstrip()
    return stripped.startswith(("//", "/*"))


# Patterns for default function names (to be used with --pedantic flag).
# Pre-compiled: W023 runs ``fullmatch`` per function in the TU.
DEFAULT_FUNC_NAME_PATTERNS = [
    re.compile(r"\bfcn\b"),
    re.compile(r"\bfn\b"),
    re.compile(r"\bfun\b"),
    re.compile(r"\bFUN_[0-9A-Fa-f]+\b"),
    re.compile(r"\bsub_[0-9A-Fa-f]+\b"),
    re.compile(r"\bfunc_[0-9A-Fa-f]+\b"),
    re.compile(r"\bthunk_[0-9A-Fa-f]+\b"),
]
_FUNC_DEF_STYLE_RE = re.compile(
    r"([a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{"
)


@dataclass
class LintResult:
    """Accumulated lint errors and warnings for a single source file.

    Why a custom linter? Standard C linters don't understand rebrew's
    annotation markers and metadata. We need strict validation to ensure
    the CI pipeline and other tools (like `rebrew test`) can parse them.
    """

    filepath: Path
    errors: list[tuple[int, str, str]] = field(default_factory=list)
    warnings: list[tuple[int, str, str]] = field(default_factory=list)
    context_prefix: str = ""
    marker_line: int = 1
    # Counters collected during lint for --summary (avoids re-reading files).
    _status_counts: Counter[str] = field(default_factory=Counter)
    _marker_counts: Counter[str] = field(default_factory=Counter)
    # Collected inline metadata for --fix migration: (module, va_int, key, value, marker)
    _inline_fixes: list[tuple[str, int, str, str, str]] = field(default_factory=list)
    # Unknown / derived-only keys (W010: SYMBOL, PROTOTYPE, …) — strip, never store.
    _inline_strips: list[tuple[str, int, str]] = field(default_factory=list)
    # Inline keys that duplicate a metadata-owned field with an equal value:
    # no warning (the store already owns the field) but --fix strips the
    # dead inline copy.  SIZE is never collected (inline SIZE is the contract).
    _inline_dup_strips: list[tuple[str, int, str]] = field(default_factory=list)
    # Lines of the file for style checks
    _lines: list[str] = field(default_factory=list)
    # Marker headers parsed from _lines — reused by the batch W029 VA index
    # instead of re-parsing every file (was a second full header pass).
    _headers: list[tuple[dict[str, str], dict[str, bool]]] | None = None

    def error(self, line: int, code: str, msg: str) -> None:
        """Record an error diagnostic at *line*."""
        self.errors.append((line, code, self.context_prefix + msg))

    def warning(self, line: int, code: str, msg: str) -> None:
        """Record a warning diagnostic at *line*."""
        self.warnings.append((line, code, self.context_prefix + msg))

    @property
    def passed(self) -> bool:
        """True if no errors were recorded."""
        return len(self.errors) == 0

    def _display_lines(self, quiet: bool = False) -> list[str]:
        """Formatted error/warning lines; callers batch them into one print."""
        rel = untrusted_ident(self.filepath.name)
        lines = [
            f"  [bold]{rel}[/bold]:{line}: [red]{code}[/red]: {untrusted_ident(msg)}"
            for line, code, msg in self.errors
        ]
        if not quiet:
            lines += [
                f"  [bold]{rel}[/bold]:{line}: [yellow]{code}[/yellow]: {untrusted_ident(msg)}"
                for line, code, msg in self.warnings
            ]
        return lines

    def display(self, quiet: bool = False) -> None:
        """Print errors (and optionally warnings) to the console."""
        lines = self._display_lines(quiet)
        if lines:
            # One console.print per call: per-line prints each paid Rich's
            # full markup+highlight+wrap pipeline (2401 calls — half of
            # batch-lint time).  highlight=False drops the ReprHighlighter
            # decoration only; the explicit colour tags above still apply.
            console.print("\n".join(lines), highlight=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        return {
            "file": str(self.filepath.name),
            "path": str(self.filepath),
            "errors": [{"line": ln, "code": c, "message": m} for ln, c, m in self.errors],
            "warnings": [{"line": ln, "code": c, "message": m} for ln, c, m in self.warnings],
            "passed": self.passed,
        }


def _parse_multi_headers(lines: list[str]) -> list[tuple[dict[str, str], dict[str, bool]]]:
    """Parse ALL annotation headers from the file.

    Returns a list of tuples: (found_keys, format_flags).
    """
    results = []
    current_keys: dict[str, str] = {}
    current_flags = {"has_new": False}
    in_block = False
    pending_kv: dict[str, str] = {}
    seen_code_after_marker: bool = False

    for line_idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue

        # NEW_FUNC_RE and NEW_KV_RE match `//` and `/*` comment lines; skip
        # the regex calls on non-comment lines (the bulk of source files).
        if not stripped.startswith(("//", "/*")):
            if in_block:
                seen_code_after_marker = True
            continue

        if NEW_FUNC_RE.match(stripped):
            if in_block:
                results.append((current_keys, current_flags))

            current_keys = dict(pending_kv)
            pending_kv = {}
            current_flags = {
                "has_new": True,
            }
            in_block = True
            seen_code_after_marker = False
            current_keys["_LINE"] = str(line_idx + 1)

            m = _HEADER_MARKER_RE.match(stripped)
            if m:
                current_keys["MARKER"] = m.group(1)
                current_keys["MODULE"] = m.group(2)
                current_keys["VA"] = m.group(3)
            continue

        m = NEW_KV_RE.match(stripped)
        if m:
            if in_block and not seen_code_after_marker:
                current_keys[m.group("key").upper()] = m.group("value").strip()
            else:
                pending_kv[m.group("key").upper()] = m.group("value").strip()
            continue

        # Any other line here is a comment (non-comment lines were handled
        # above): a bare function-name hint (``// Foo``), an explanation, or
        # a ``/* ... */`` block.  A comment is not code — keep the header
        # block open so a following ``// SIZE:``/``// CFLAGS:``/etc. still
        # attaches to the marker block (mirrors annotation.py's name-hint
        # handling; without this, the name line orphaned later KV keys and
        # W019/--fix could never see them).

    if in_block:
        results.append((current_keys, current_flags))

    return results


def _w019_key_backed(
    key: str,
    block: tuple[str, str, int],
    fn_entries: dict[tuple[str, int], dict[str, Any]],
    data_entries: dict[tuple[str, int], dict[str, Any]],
    lowered_keys: dict[tuple[str, int, str], frozenset[str]] | None = None,
) -> bool:
    """True when the metadata store already owns *key* for *block*'s function.

    The DATA/GLOBAL overlay: for those blocks only size/section/note are
    sourced from rebrew-data.toml; everything else comes from
    rebrew-functions.toml.  Shared by W019's check and
    :func:`count_migratable_files` so the two can never disagree.

    *lowered_keys* is an optional ``{(module, va, "fn"|"data"): frozenset}``
    cache of the entries' lowercased field names.  A caller that checks many
    keys against one store passes one in; without it each call rebuilds the
    set, which is a fresh allocation per (file, block, key) triple over the
    whole tree.
    """
    marker_type, module, va = block
    mod_va = (module, va)

    if marker_type in DATA_MARKERS:
        if key.lower() in {"size", "section", "note"}:
            if lowered_keys is not None:
                cache_key = (module, va, "data")
                names = lowered_keys.get(cache_key)
                if names is None:
                    names = frozenset(k.lower() for k in data_entries.get(mod_va, {}))
                    lowered_keys[cache_key] = names
            else:
                names = frozenset(k.lower() for k in data_entries.get(mod_va, {}))
            return key.lower() in names
        return False
    if lowered_keys is not None:
        cache_key = (module, va, "fn")
        names = lowered_keys.get(cache_key)
        if names is None:
            names = frozenset(k.lower() for k in fn_entries.get(mod_va, {}))
            lowered_keys[cache_key] = names
    else:
        names = frozenset(k.lower() for k in fn_entries.get(mod_va, {}))
    return key.lower() in names


def count_migratable_files(
    src_dir: Path, cfg: Any, *, sources: Sequence[Path] | None = None
) -> int:
    """Return the number of source files ``rebrew lint --fix`` can migrate.

    The count twin of W019 (see ``_check_W019_inline_metadata``): a file
    counts when an inline metadata key is attached to a marker header block
    — found by the *same* header parser ``rebrew lint`` itself uses, so
    block attachment cannot drift — and that field is NOT already owned by
    the metadata store.  Markerless occurrences (the ``// CFLAGS:
    /DREBREW_ALLOW_NAKED`` naked-guard convention), ``// SIZE:`` (the
    reccmp-native inline contract) and keys already backed by metadata are
    deliberately not counted, so the "run rebrew lint to migrate" hint is
    always actionable.

    Only scans files returned by ``iter_sources`` so that the extension
    filter (``cfg.source_ext``) is respected.  *sources* is that list when the
    caller already holds it, sparing a whole-tree walk.
    """
    fn_entries = load_metadata(cfg.metadata_dir, deepcopy=False)
    data_entries = load_data_metadata(cfg.metadata_dir)
    count = 0
    # One lowercased field-name set per metadata entry, reused across every
    # key of every block in the tree.
    lowered_keys: dict[tuple[str, int, str], frozenset[str]] = {}
    for src in iter_sources(src_dir, cfg) if sources is None else sources:
        try:
            lines = split_source_lines(read_source_text(src)[0])
        except OSError as exc:
            # A file that cannot be read would otherwise contribute zero
            # inline keys and no diagnostics, so lint would call the tree
            # clean and `--fix` would report nothing to migrate.
            logging.getLogger(__name__).warning("could not read %s: %s", src, exc)
            continue
        for found_keys, _flags in _parse_multi_headers(lines):
            marker = found_keys.get("MARKER", "")
            module = found_keys.get("MODULE", "")
            va_hex = found_keys.get("VA", "")
            if not (marker and module and va_hex):
                continue
            # Guarded like every other VA conversion in this module: a
            # malformed VA must skip the block, not raise out of a counter.
            try:
                block = (marker, module, int(va_hex, 16))
            except ValueError:
                continue
            for key, value in found_keys.items():
                if key not in METADATA_KEYS:
                    continue
                if key == "SIZE":
                    continue
                if key == "SOURCE" and value.strip().lower() == "naked":
                    continue
                if not _w019_key_backed(
                    key, block, fn_entries, data_entries, lowered_keys=lowered_keys
                ):
                    count += 1
                    break
    return count


def _check_format_errors(result: LintResult, flags: dict[str, bool]) -> bool:
    """Check format-level errors (E001). Returns True if validation should proceed."""
    if not flags["has_new"]:
        result.error(result.marker_line, "E001", "Missing FUNCTION/LIBRARY/STUB annotation")
        return False

    return True


def _check_E001_marker(result: LintResult, marker: str) -> None:
    if marker not in VALID_MARKERS:
        result.error(result.marker_line, "E001", f"Invalid marker type: {marker}")


def _check_E002_va(result: LintResult, va_str: str, min_va: int = MIN_VALID_VA) -> int | None:
    try:
        va_int = int(va_str, 16)
        if not (min_va <= va_int <= 0xFFFFFFFF):
            result.error(result.marker_line, "E002", f"VA {va_str} is suspicious (outside range)")
        return va_int
    except ValueError:
        result.error(result.marker_line, "E002", f"Invalid VA format: {va_str}")
        return None


def _check_E013_duplicate_va(
    result: LintResult,
    va_int: int | None,
    va_str: str,
    filepath: Path,
    seen_vas: dict[Any, str] | None,
    module: str = "",
    marker: str = "",
    lines: list[str] | None = None,
    marker_line: int = 0,
    seen_va_defines: dict[Any, bool] | None = None,
) -> None:
    if va_int is None or seen_vas is None:
        return
    # Key on (module, va) so a multi-module file whose blocks share a VA
    # (a valid layout) is not flagged, while a true duplicate — same module
    # + VA, in the same or another file — is.
    key: Any = (module, va_int) if module else va_int
    defines = _block_defines(lines, marker_line) if marker in DATA_MARKERS else True
    if key in seen_vas:
        # Data-marker duplicates collide only when BOTH sides define the
        # symbol (two initializers = LNK4006 risk).  The normal
        # progressive-ownership shape — owner TU extern-declares (or bare
        # claim) while link scaffolding holds the single definition — is
        # unambiguous and must not fail the gate.
        if marker in DATA_MARKERS and not (defines and (seen_va_defines or {}).get(key, False)):
            if seen_va_defines is not None:
                seen_va_defines[key] = seen_va_defines.get(key, False) or defines
            seen_vas[key] = f"{rel_display_path(filepath)}"
            return
        result.error(result.marker_line, "E013", f"Duplicate VA {va_str} — also in {seen_vas[key]}")
    else:
        if seen_va_defines is not None:
            seen_va_defines[key] = defines
        seen_vas[key] = rel_display_path(filepath)


def _block_defines(lines: list[str] | None, marker_line: int) -> bool:
    """True when the declaration after a marker line is a definition.

    Skips blanks/comments; a first code line with an initializer (``=``)
    that is not ``extern`` counts as a definition.  Tentative definitions
    (``int x;``) and pure markers (next marker follows) do not.
    """
    if not lines or marker_line < 1:
        return False
    for raw in lines[marker_line:]:
        stripped = raw.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        if stripped.startswith("extern"):
            return False
        return "=" in stripped
    return False


def _function_containing_va(
    spans: list[tuple[int, int, str]], va: int
) -> tuple[int, int, str] | None:
    """Return the ``(start, end, name)`` span containing *va*, or None.

    ``spans`` is a list sorted by start.  A span whose *start* equals *va*
    is NOT a "contains" — the caller already established that *va* is not a
    function start, so only strictly-inside hits qualify (a moved/merged
    annotation now points into the body of a different function).  A shorter
    span nested in a longer one does not hide the outer tail.
    """
    if not spans or va <= spans[0][0]:
        return None
    # bisect the span tuples themselves against (va, +inf, ""): the second and
    # third elements only break ties at an exact start match, so the probe
    # lands on the last span whose start is <= va, as a starts list did.
    idx = bisect.bisect_right(spans, (va, float("inf"), "")) - 1
    # The latest start is not enough: a shorter span nested in a longer one
    # hides the outer tail. Walk back to the nearest span that still covers va.
    while idx >= 0:
        start, end, name = spans[idx]
        if start < va < end:
            return (start, end, name)
        idx -= 1
    return None


def _build_function_index(
    cfg: ProjectConfig,
) -> tuple[set[int], list[tuple[int, int, str]]] | None:
    """Build ``(starts, spans)`` from the target's function list, or None.

    ``starts`` is the set of function-start VAs; ``spans`` is the sorted
    ``(start, end, name)`` list used to detect annotations that fell inside
    another function after a move/merge.  Returns None when the list is
    missing or empty — the W028 check is then silent (nothing to check
    against), matching the old doctor behavior.
    """
    from rebrew.catalog import cached_function_list

    funcs = cached_function_list(cfg)
    if not funcs:
        return None
    starts: set[int] = set()
    spans: list[tuple[int, int, str]] = []
    for f in funcs:
        raw_va = f.get("va")
        if raw_va is None:
            continue
        va = int(raw_va)
        # 16-bit DOS targets address code from segment 0, so VA 0 is legitimate
        # there (min_valid_va_for returns 0) — dropping it fired a false W028 on
        # every `// FUNCTION: GAME 0x0` annotation.
        if va < min_valid_va_for(cfg):
            continue
        starts.add(va)
        spans.append((va, va + max(int(f.get("size", 0) or 0), 1), str(f.get("name", ""))))
    spans.sort()
    return starts, spans


def _staleness_fix(cfg: ProjectConfig | None) -> str:
    """Pick a staleness fix hint from which artifact is newer.

    Stale annotations have two very different causes: the target binary was
    replaced (refresh the function inventory), or the annotations moved / the inventory
    no longer reflects the target (re-annotate) — recommending ``rebrew
    intake`` for the second case is wrong.  The binary-vs-list mtime
    comparison is a cheap proxy: a binary newer than the list means it
    plausibly changed after the list was written; a list at least as new as
    the binary means the binary cannot have changed since, so the markers
    (or a list regenerated from a different binary, e.g. a rebuild) are at
    fault.  Falls back to a cause-neutral message when either file's mtime
    is unavailable.
    """
    binary_newer: bool | None = None
    try:
        bin_path = Path(str(getattr(cfg, "target_binary", "")))
        rev_dir = getattr(cfg, "reversed_dir", None)
        inv_path = inventory_path_for(rev_dir, cfg) if rev_dir else None
        if inv_path is not None and bin_path.is_file() and inv_path.is_file():
            # Nanosecond mtimes: second-granularity floats tie when a rebuild
            # and inventory refresh land in the same wall-clock second (common
            # on scripts / coarse Docker volume clocks), flipping the hint.
            binary_newer = bin_path.stat().st_mtime_ns > inv_path.stat().st_mtime_ns
    except OSError:
        binary_newer = None

    annotate = "re-annotate the moved functions (`rebrew skeleton <new_va>` or edit the marker VA)"
    if binary_newer is True:
        return (
            "The target binary is newer than the function inventory — it likely changed: "
            "re-run `rebrew intake` / `rebrew discover-functions` to refresh it, then " + annotate
        )
    if binary_newer is False:
        return (
            "The function inventory is as new as the target binary, so the binary did not "
            "change: " + annotate + ". If the inventory was regenerated from a different "
            "binary (e.g. a rebuilt artifact) instead of the target, regenerate it "
            "from the target"
        )
    return (
        "The function inventory no longer matches these annotations: if the target binary "
        "changed, re-run `rebrew intake` / `rebrew discover-functions` to refresh it; "
        "otherwise " + annotate + " (or regenerate the inventory if it was built from a "
        "different binary, e.g. a rebuilt artifact)"
    )


def _check_W028_stale_annotation(
    result: LintResult,
    va_int: int,
    module: str,
    cfg: ProjectConfig | None,
    function_index: tuple[set[int], list[tuple[int, int, str]]] | None,
    status: str = "",
    metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> None:
    """Warn when a FUNCTION/STUB marker VA matches no function start (W028).

    A "stale annotation" is a ``// FUNCTION:``/``// STUB:`` marker whose VA
    no longer corresponds to a function in the current binary.  After a
    binary update or a re-discovery the function either moved — the marker
    now points *inside* another function's span — or was removed (no
    function at that VA).  Either way ``rebrew test``/``verify`` compile
    against the wrong bytes and status/todo keep reporting phantom
    functions.

    Uses the target's discovery inventory (the same file ``rebrew intake`` /
    ``discover`` write) as ground truth.  ``LIBRARY`` markers are excluded
    (import stubs) and ``GLOBAL``/``DATA`` markers are data, not code;
    markers of a different target module are filtered by the caller's
    config.  Silent when no function index is available.
    """
    if function_index is None:
        return
    marker = getattr(cfg, "marker", None) if cfg is not None else None
    if marker and module and module != marker:
        return  # another target's marker — E012 already flags the module
    starts, spans = function_index
    if va_int in starts:
        return
    # A byte-matched annotation outranks the inventory.  The inventory comes
    # from heuristic discovery (rizin + a capstone sweep), which merges
    # adjacent functions when the boundary is only `ret` + alignment padding;
    # EXACT/RELOC means this VA already compiled and compared byte-for-byte
    # against the target there, which is strictly stronger evidence than a
    # sweep's guess.  Warning on those is a false positive that cannot be
    # actioned -- "re-annotate the marker VA" would break a matched function.
    # guild-rebrew hit 15 of these at once, including an EXACT row whose
    # supposed host was split from it by `ret; nop; nop` at 0x1000d92d.
    if status.upper() in MATCHED_STATUSES:
        return
    host = _function_containing_va(spans, va_int)
    # The same merge, shown by the annotations themselves: the host's start is
    # an annotated function whose SIZE ends at or before this marker, so the
    # two annotations tile the host's range and discovery joined them.
    if host is not None and metadata is not None:
        try:
            host_size = int(metadata.get((module, host[0]), {}).get("size") or 0)
        except (TypeError, ValueError):
            host_size = 0
        if host_size and host[0] + host_size <= va_int:
            return
    # Append the mtime-aware fix hint only to the first stale marker in the
    # file — repeating it per marker would drown the signal.
    hint = _staleness_fix(cfg) if not any(c == "W028" for _, c, _ in result.warnings) else ""
    if host is not None:
        result.warning(
            result.marker_line,
            "W028",
            f"annotation VA 0x{va_int:x} points inside function "
            f"'{host[2] or 'a function'}' (moved/merged) — re-annotate the "
            "marker VA or refresh the function inventory (`rebrew discover-functions`)" + hint,
        )
    else:
        result.warning(
            result.marker_line,
            "W028",
            f"annotation VA 0x{va_int:x} has no function in the current "
            "function inventory (removed or shifted) — re-annotate the marker VA "
            "or refresh the function inventory (`rebrew discover-functions`)" + hint,
        )


def _check_W030_va_order(result: LintResult, all_headers: list[Any], lines: list[str]) -> None:
    """Warn when a module's FUNCTION/STUB definitions do not ascend by VA (W030).

    The linker lays out a translation unit's functions in source order, so a
    definition placed above a lower-VA one links at the wrong address and
    displaces every function between them.  Markers with only comments or
    blank lines between them share one body (identical copies at several VAs)
    and count as one definition, placed by its lowest VA.  Each module is
    checked on its own: a marker for another build carries that build's VA.
    """
    groups: list[dict[str, tuple[int, int]]] = []
    prev_line = -1
    for found_keys, _flags in all_headers:
        if found_keys.get("MARKER", "") not in ("FUNCTION", "STUB"):
            continue
        try:
            va = int(found_keys.get("VA", ""), 16)
        except ValueError:
            continue
        line = int(found_keys.get("_LINE", "1"))
        between = lines[prev_line : line - 1] if prev_line >= 0 else ["code"]
        if not groups or any(t.strip() and not t.lstrip().startswith("//") for t in between):
            groups.append({})
        mod = found_keys.get("MODULE", "")
        cur = groups[-1].get(mod)
        groups[-1][mod] = (va, line) if cur is None else (min(va, cur[0]), cur[1])
        prev_line = line
    highest: dict[str, int] = {}
    for group in groups:
        for mod, (va, line) in group.items():
            prev = highest.get(mod)
            if prev is not None and va < prev:
                result.warning(
                    line,
                    "W030",
                    f"{mod} 0x{va:x} is defined after {mod} 0x{prev:x}: the linker places "
                    "functions in source order, so move this definition above the "
                    "higher-VA one",
                )
            highest[mod] = va if prev is None else max(prev, va)


def _check_W018_cflags(
    result: LintResult, found_keys: dict[str, str], cfg: ProjectConfig | None
) -> None:
    has_annotation = "CFLAGS" in found_keys and found_keys["CFLAGS"].strip()
    if has_annotation:
        return
    # Only warn if the target config also has no default cflags.  cfg.cflags
    # (the user-facing default, empty when unset) is the right fallback —
    # cfg.base_cflags is always-on /nologo /c /MT glue, so checking it would
    # make this warning never fire.
    has_config_default = bool(getattr(cfg, "cflags", "") if cfg else "")
    if not has_config_default:
        result.warning(
            result.marker_line,
            "W018",
            "Missing CFLAGS in metadata and no default cflags in project config",
        )


# Unknown keys that are safe for `--fix` to strip outright: retired
# annotations whose value is now derived from the C source itself, so the
# inline line carries no information (SYMBOL from the function definition,
# PROTOTYPE from the definition line).  Any other unknown key is only
# warned about — it may be a typo of a real key or a prose note, and
# deleting it would destroy information.
_FIXABLE_UNKNOWN_KEYS = frozenset({"SYMBOL", "PROTOTYPE"})

# Statuses that carry no claim about a function's body, so they cannot
# contradict what a check found. A file claiming only these does not gain
# a "but STATUS claims ..." suffix.
_UNCLAIMED_STATUSES = frozenset({"STUB", "SKIP"})


def _check_W010_unknown_keys(
    result: LintResult,
    found_keys: dict[str, str],
    module: str = "",
    va_int: int | None = None,
) -> None:
    for key in found_keys:
        if key in ALL_KNOWN_KEYS or key in ("MODULE", "_LINE") or key.startswith("_"):
            continue
        result.warning(result.marker_line, "W010", f"Unknown annotation key: {key}")
        if module and va_int is not None and key in _FIXABLE_UNKNOWN_KEYS:
            result._inline_strips.append((module, va_int, key))


def _check_E015_marker_consistency(
    result: LintResult, marker: str, module: str, status: str, cfg: ProjectConfig | None = None
) -> None:
    # E015's intent is library-module attribution: a FUNCTION marker on a
    # module configured as library should be LIBRARY.  A STUB-status function
    # may legitimately keep either its STUB marker or the FUNCTION marker
    # (status lives in rebrew-functions.toml per the metadata convention), so
    # both are allowed; anything else is inconsistent.
    lib_modules = cfg.library_modules if cfg and cfg.library_modules is not None else set()
    if module in lib_modules:
        expected_marker = "LIBRARY"
        allowed = {"LIBRARY"}
    elif status == "STUB":
        expected_marker = "FUNCTION"
        allowed = {"FUNCTION", "STUB"}
    else:
        expected_marker = "FUNCTION"
        allowed = {"FUNCTION"}
    if marker not in allowed and marker in VALID_MARKERS and marker not in DATA_MARKERS:
        result.error(
            result.marker_line,
            "E015",
            f"Marker {marker} inconsistent with module {module!r} (expected {expected_marker})",
        )


def _check_E004_status_value(result: LintResult, status: str) -> None:
    """A persisted STATUS outside KNOWN_STATUSES is a typo/legacy value.

    ``canonical_status`` upper-cases and maps the ``NEAR_MATCH`` alias; an
    unknown word still flows through the overlay as if valid, so flag it
    instead of silently treating it as a real classification.
    """
    if status and canonical_status(status) not in KNOWN_STATUSES:
        result.error(
            result.marker_line,
            "E004",
            f"Unknown STATUS {status!r}; known values: {', '.join(sorted(KNOWN_STATUSES))}",
        )


def _check_E008_size_value(result: LintResult, metadata_size: str | None) -> None:
    """A metadata SIZE that is not an integer misleads byte extraction.

    Validates the ``rebrew-functions.toml`` value only: ``// SIZE:`` inline is
    the reccmp-native contract (see W019) and is not part of this rule, matching
    the reserved E008 scope.  A non-numeric *metadata* SIZE would make a
    consumer slice the wrong byte count or silently fall back.
    """
    if not metadata_size:
        return
    try:
        int(metadata_size, 0)
    except ValueError:
        result.error(
            result.marker_line, "E008", f"metadata SIZE {metadata_size!r} is not an integer"
        )


def _check_E017_contradictory(result: LintResult, status: str, marker: str) -> None:
    if status == "NEAR_MATCHING" and marker == "STUB":
        result.error(
            result.marker_line, "E017", f"Contradictory: status is {status} but marker is STUB"
        )
    elif marker == "STUB" and status in EARNED_STATUSES:
        # A byte-matched or proven function marked STUB (stale marker from
        # stub generation, metadata later promoted).  The STUB marker hides a
        # developed function from status/todo and misleads reversers.
        result.error(
            result.marker_line,
            "E017",
            f"Contradictory: status is {status} but marker is STUB — "
            "remove the stale STUB marker (function is developed)",
        )


def _check_W005_blocker(result: LintResult, status: str, found_keys: dict[str, str]) -> None:
    # BLOCKER lives in rebrew-functions.toml metadata; the metadata overlay already injects it
    # into found_keys before this check runs, so this fires only when absent from both.
    if status == "STUB" and "BLOCKER" not in found_keys:
        result.warning(
            result.marker_line,
            "W005",
            "STUB function missing 'blocker' explanation "
            '(run: rebrew blocker set <file|0xVA> "<reason>" — or: rebrew diff --fix-blocker)',
        )


def _check_W006_source(
    result: LintResult, module: str, found_keys: dict[str, str], cfg: ProjectConfig | None = None
) -> None:
    lib_modules = cfg.library_modules if cfg and cfg.library_modules is not None else set()
    if module in lib_modules and "SOURCE" not in found_keys:
        result.warning(
            result.marker_line,
            "W006",
            f"Library module {module!r} missing // SOURCE: marker "
            "(reference file, e.g. SBHEAP.C:195 or deflate.c)",
        )


def _check_W015_va_case(result: LintResult, va_str: str) -> None:
    if va_str and va_str.startswith("0x"):
        hex_digits = va_str[2:]
        if hex_digits != hex_digits.lower() and hex_digits != hex_digits.upper():
            result.warning(
                result.marker_line,
                "W015",
                f"VA '{va_str}' has mixed-case hex digits (prefer consistent case)",
            )


def _check_W031_metadata_store(cfg: ProjectConfig) -> list[LintResult]:
    """W031: the metadata TOMLs carry something a reader will not honour.

    The gated writers reject these shapes, so a file that holds one was edited
    by hand (or written by an older tree): an unknown field, a STATUS outside
    the store's vocabulary, half a provenance pair, a provenance tag outside
    :data:`rebrew.metadata.PROVENANCE_TAGS`, a top-level key that is neither the
    format stamp nor a ``MODULE.0xVA`` entry, or a missing / foreign format
    stamp.  A reader drops an unknown key silently and falls back to the
    default, so the symptom is a flag that "did not apply" with nothing to
    explain it.  Warn-only, reported per entry: the rest of the store loads.
    """
    from rebrew.data_metadata import (
        DATA_METADATA_FIELDS,
        DATA_METADATA_FILENAME,
        DATA_STATUSES,
    )
    from rebrew.metadata import FORMAT_KEY, FORMAT_VERSION, PROVENANCE_TAGS
    from rebrew.metadata_doc import parse_metadata_key
    from rebrew.utils import load_tomllib

    results: list[LintResult] = []

    def check_store(
        path: Path,
        fields: frozenset[str],
        statuses: frozenset[str] | None,
    ) -> None:
        if not path.is_file():
            return
        try:
            doc = load_tomllib(path)
        except (OSError, ValueError) as exc:
            # Returning here would report a clean run over a store this check
            # could not read, losing every W031 finding it holds.
            res = LintResult(path)
            res.warning(1, "W031", f"store could not be parsed, contents unchecked: {exc}")
            results.append(res)
            return
        if not isinstance(doc, dict):
            res = LintResult(path)
            res.warning(1, "W031", "store is not a TOML table, contents unchecked")
            results.append(res)
            return
        problems: list[str] = []
        stamp = doc.get(FORMAT_KEY)
        if stamp is None:
            problems.append(
                f"no {FORMAT_KEY} stamp (a writer adds {FORMAT_KEY} = {FORMAT_VERSION})"
            )
        elif stamp != FORMAT_VERSION:
            problems.append(f"{FORMAT_KEY} = {stamp!r}, this rebrew reads {FORMAT_VERSION}")
        known_fields = {f.upper() for f in fields}
        for key, entry in doc.items():
            if key == FORMAT_KEY:
                continue
            if not isinstance(entry, dict):
                problems.append(
                    f"top-level {key!r} is neither {FORMAT_KEY!r} nor a MODULE.0xVA entry"
                )
                continue
            if parse_metadata_key(key) is None:
                problems.append(f"top-level {key!r} is not a MODULE.0xVA entry")
            lower = {str(k).lower() for k in entry}
            for name in entry:
                if str(name).upper() not in known_fields:
                    problems.append(f"{key}: unknown field {name!r} (every reader ignores it)")
            status = str(entry.get("status") or "")
            if statuses is not None and status and status not in statuses:
                problems.append(
                    f"{key}: STATUS {status!r} is not one of {', '.join(sorted(statuses))}"
                )
            if ("updated_by" in lower) != ("updated_at" in lower):
                problems.append(
                    f"{key}: half a provenance pair (updated_by / updated_at are written together)"
                )
            tag = str(entry.get("updated_by") or "")
            if tag and tag not in PROVENANCE_TAGS:
                problems.append(f"{key}: unknown provenance tag {tag!r}")
        if problems:
            res = LintResult(path)
            for problem in problems:
                res.warning(1, "W031", problem)
            results.append(res)

    # METADATA_FIELDS is upper-case while MARKER_IDENTITY_FIELDS is lower-case
    # (`file`, `symbol`, `name`, `marker_type`): compare both spellings, or a
    # `migrate-markers` identity field reads as unknown.
    function_fields = frozenset(f.upper() for f in METADATA_FIELDS) | frozenset(
        f.upper() for f in MARKER_IDENTITY_FIELDS
    )
    check_store(
        (Path(cfg.metadata_dir) / "rebrew-functions.toml").resolve(),
        function_fields,
        None,
    )
    check_store(
        (Path(cfg.metadata_dir) / DATA_METADATA_FILENAME).resolve(),
        DATA_METADATA_FIELDS,
        DATA_STATUSES,
    )
    return results


def _check_W034_identity_paths(cfg: ProjectConfig) -> list[LintResult]:
    """W034: a stored ``file`` identity that a consumer cannot safely join.

    ``verify`` compiles ``reversed_dir / file``, ``rename`` rewrites it, and
    BinSync reads it, so an absolute path or a ``..`` segment names a file the
    metadata's author chose rather than one in this checkout.  Writers refuse
    it now (:func:`rebrew.metadata.validate_identity_file`); this reports rows
    that were written before the gate, or edited by hand.
    """
    from rebrew.metadata import validate_identity_file
    from rebrew.utils import load_tomllib

    path = (Path(cfg.metadata_dir) / "rebrew-functions.toml").resolve()
    if not path.is_file():
        return []
    try:
        doc = load_tomllib(path)
    except (OSError, ValueError) as exc:
        # An unreadable store hides every W034 finding in it, which reads as a
        # clean run over identities this check never saw.
        res = LintResult(path)
        res.warning(1, "W034", f"store could not be parsed, identities unchecked: {exc}")
        return [res]
    if not isinstance(doc, dict):
        res = LintResult(path)
        res.warning(1, "W034", "store is not a TOML table, identities unchecked")
        return [res]
    problems: list[str] = []
    for key, entry in doc.items():
        if not isinstance(entry, dict):
            continue
        value = str(entry.get("file") or "")
        if not value:
            continue
        try:
            validate_identity_file(value)
        except ValueError as exc:
            problems.append(f"{key}: {exc}")
    if not problems:
        return []
    res = LintResult(path)
    for problem in problems:
        res.warning(1, "W034", problem)
    return [res]


def _check_W035_unknown_modules(cfg: ProjectConfig) -> list[LintResult]:
    """W035: a store row whose module belongs to no target in this project.

    ``status`` / ``todo`` / the dashboards filter rows by module, so a row left
    behind by a renamed target is invisible everywhere while still sitting in
    the store.  Known modules are the project marker, every target marker, and
    the declared library modules.
    """
    from rebrew.metadata import load_metadata

    known = {preset_module_key(str(getattr(cfg, "marker", "") or ""))}
    known |= {preset_module_key(str(name)) for name in (getattr(cfg, "all_markers", None) or ())}
    known |= {
        preset_module_key(str(name)) for name in (getattr(cfg, "library_modules", None) or ())
    }
    known.discard("")
    if not known:
        return []
    unknown = sorted(
        {
            str(module)
            for (module, _va) in load_metadata(cfg.metadata_dir, deepcopy=False)
            if preset_module_key(str(module)) not in known
        }
    )
    if not unknown:
        return []
    res = LintResult(Path("rebrew-functions.toml"))
    for module in unknown:
        res.warning(
            1,
            "W035",
            f"module {module!r} matches no target marker or library module"
            " (rows for a renamed or removed target stay invisible to status/todo)",
        )
    return [res]


#: Old-store artifacts the coverage document replaced.  A tree that still
#: carries one has coverage the dashboards do not read, which is the failure
#: this check exists to make visible (the readers glob coverage-*.toml only).
_STALE_COVERAGE_ARTIFACTS: dict[str, str] = {
    "coverage.db": (
        "leftover SQLite coverage database — the store is now one clear-text "
        "db/coverage-<target>.toml per target; re-run rebrew build-db and delete this"
    ),
    # The verify cache and its --compare baseline moved from JSON to TOML with
    # the other stores.  A leftover JSON file is not read any more, so the
    # verdicts it holds are invisible: name it rather than let the next verify
    # silently start from a cold cache.
    "verify_cache.json": (
        "leftover JSON verify cache — the store is .rebrew/verify_cache.toml now "
        "(same rows, TOML); re-run rebrew verify and delete this"
    ),
    "verify_baseline.json": (
        "leftover JSON compare baseline — the --compare baseline is "
        ".rebrew/verify_baseline.toml now; re-run rebrew verify --compare and delete this"
    ),
}


def _check_W036_stray_metadata_store(cfg: ProjectConfig) -> list[LintResult]:
    """W036: a metadata store living outside the directory the readers use.

    The stores are resolved by directory, not by search: a tool asked for a
    module reads ``<metadata_dir>/rebrew-data.toml`` and gets **whatever is
    there**, with no fallback to another copy.  So a second ``rebrew-data.toml``
    somewhere else in the tree is not a backup -- it is a file that answers for
    a directory if a tool is pointed at it, and is invisible otherwise.

    Measured on guild-rebrew (round 162): a stray ``./rebrew-data.toml`` at the
    project root held **1** entry while ``src/rebrew-data.toml`` held **1170**,
    and `rebrew lint` reported 0 warnings.  Loaded against the root, the store
    resolves and returns the 1 entry with no complaint.

    Warn-only: a stray copy is not itself a defect, it is a thing that will be
    read by accident.
    """
    store_names = {"rebrew-data.toml", "rebrew-functions.toml"}
    dirs: set[Path] = set()
    for attr in ("metadata_dir", "reversed_dir", "shared_dir"):
        value = getattr(cfg, attr, None)
        if value:
            dirs.add(Path(value).resolve())
    results: list[LintResult] = []
    skip = {".git", "build", ".scratch", "node_modules", ".venv"}
    for path in sorted(cfg.root.rglob("*.toml")):
        if path.name not in store_names:
            continue
        if any(part in skip for part in path.parts):
            continue
        if path.parent.resolve() in dirs:
            continue
        res = LintResult(filepath=path)
        res.warning(
            1,
            "W036",
            "metadata store outside the configured directory; readers resolve "
            "stores by directory, so this one answers for "
            f"{path.parent} and is invisible otherwise",
        )
        results.append(res)
    return results


def _check_W032_coverage_store(cfg: ProjectConfig) -> list[LintResult]:
    """W032: the coverage store's own hygiene.

    Two failures the readers hide: an artifact from a store that no longer
    exists (`coverage.db`, the grid JSON, the catalog CSV) sitting beside the
    documents, and a `coverage-<target>.toml` the dashboards cannot serve —
    malformed, a foreign `version`, or a `target` key that disagrees with the
    filename, so that target answers with another's data.
    """
    from rebrew.coverage_toml import CoverageTomlError, load_coverage_from
    from rebrew.workspace import db_dir

    directory = db_dir(cfg.root)
    if not directory.is_dir():
        return []
    results: list[LintResult] = []
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        name = path.name
        message = ""
        if name in _STALE_COVERAGE_ARTIFACTS:
            message = _STALE_COVERAGE_ARTIFACTS[name]
        elif name.startswith("data_") and path.suffix == ".json":
            message = (
                "leftover catalog grid JSON — rebrew build-db renders the "
                "document in process now; delete this"
            )
        elif path.suffix == ".csv":
            message = "leftover catalog CSV export — rebrew no longer writes it; delete this"
        elif name.startswith("coverage-") and path.suffix == ".toml":
            # The documented filename pattern; the reader's own prefix/suffix
            # constants are private to coverage_toml.  The loader already
            # refuses a foreign `version`, malformed TOML, and a `target` key
            # that disagrees with the filename, so one read covers all three.
            target = name[len("coverage-") : -len(".toml")]
            try:
                load_coverage_from(directory, target)
            except CoverageTomlError as exc:
                message = (
                    f"coverage document the dashboards cannot serve ({exc}) — "
                    "re-run rebrew build-db"
                )
        if message:
            res = LintResult(path)
            res.warning(1, "W032", message)
            results.append(res)
    return results


def _check_W033_agent_scaffold(cfg: ProjectConfig) -> list[LintResult]:
    """W033: the rendered agent workflow instructions have drifted.

    ``rebrew init`` writes `AGENTS.md`, `PRINCIPLES.md` and `.agents/skills/`
    from the packaged sources; an installed rebrew that gained a workflow fact
    (a new command, a new lint code, a store the tools now read) leaves every
    existing project describing the old one, and an agent follows the file it
    finds.  Compared against the same public renderer `--refresh-agents` uses,
    so the check cannot drift from the fix.  `AGENTS.md` is not compared here:
    its content is profile-rendered, and `rebrew init --refresh-agents --check`
    covers it with the full report.
    """
    from rebrew.init import agent_skill_files

    # The render needs the target name to substitute `<target>`; a config
    # without one (a bare file list, an out-of-project run) cannot be compared,
    # and guessing would flag a project that is not wrong.
    target_name = str(getattr(cfg, "target_name", "") or "")
    if not target_name or not getattr(cfg, "root", None):
        return []

    expected = {
        f".agents/skills/{rel}": data for rel, data in agent_skill_files(target_name).items()
    }
    principles = Path(__file__).parent / "PRINCIPLES.md"
    if principles.is_file():
        expected["PRINCIPLES.md"] = principles.read_bytes()

    drifted: list[str] = []
    for rel, want in sorted(expected.items()):
        path = Path(cfg.root) / rel
        if not path.is_file() or path.read_bytes() != want:
            drifted.append(rel)
    # A rendered skill file the packaged tree no longer ships is stale too
    # (`--refresh-agents` prunes it): the agent would read a workflow that
    # describes commands the installed rebrew does not have.
    skills_root = Path(cfg.root) / ".agents" / "skills"
    if skills_root.is_dir():
        # Paths relative to the skills root, the unit the listing yields.
        prefix = ".agents/skills/"
        packaged = {rel[len(prefix) :] for rel in expected if rel.startswith(prefix)}
        for path in sorted(skills_root.rglob("*")):
            rel = path.relative_to(skills_root).as_posix()
            # `.rebrew-scaffold.json` is the render manifest `--refresh-agents`
            # writes beside the skills, not a skill; a dotfile is never one.
            if path.is_file() and not rel.startswith(".") and rel not in packaged:
                drifted.append(f".agents/skills/{rel}")
    if not drifted:
        return []

    res = LintResult(Path("AGENTS.md"))
    shown = ", ".join(drifted[:6]) + (f", +{len(drifted) - 6} more" if len(drifted) > 6 else "")
    res.warning(
        1,
        "W033",
        f"{len(drifted)} generated instruction file(s) differ from the installed "
        f"rebrew ({shown}) — run rebrew init --refresh-agents",
    )
    return [res]


def _check_config_rules(
    result: LintResult, found_keys: dict[str, str], cfg: ProjectConfig | None
) -> None:
    """Config-aware checks (E012).

    A stacked shared-source marker for ANOTHER target (``// FUNCTION: V1``
    in a file linted under V2) is not a mismatch: one ``src/shared`` file
    serves every target with one marker per target (ADR-010).  Accept any
    module that names a known project target; only a module naming NO
    target fires E012.
    """
    if cfg is None:
        return

    module = found_keys.get("MODULE", "")
    marker = getattr(cfg, "marker", None)
    if module and marker and preset_module_key(module) != preset_module_key(str(marker)):
        known = {preset_module_key(str(marker))} | {
            preset_module_key(str(item))
            for item in (getattr(cfg, "all_markers", None) or ())
            if item
        }
        if preset_module_key(module) in known:
            return
        result.error(
            result.marker_line,
            "E012",
            f"Module '{module}' doesn't match configured marker '{marker}'",
        )


@dataclass(frozen=True)
class MissingSection:
    """A DATA/GLOBAL marker whose VA resolves to a known binary section (W016)."""

    module: str
    va: int
    section: str


def _check_W016_section(
    result: LintResult,
    marker: str,
    found_keys: dict[str, str],
    module: str = "",
    va_int: int | None = None,
    section_for_va: Any = None,
    section_hits: list[MissingSection] | None = None,
) -> None:
    if marker in DATA_MARKERS and "SECTION" not in found_keys:
        result.warning(
            result.marker_line,
            "W016",
            f"{marker} marker missing // SECTION: (.data, .rdata, .bss)",
        )
        if (
            module
            and va_int is not None
            and section_for_va is not None
            and section_hits is not None
        ):
            section = section_for_va(va_int)
            if section:
                section_hits.append(MissingSection(module=module, va=va_int, section=section))


def _check_W019_inline_metadata(
    result: LintResult,
    found_keys: dict[str, str],
    metadata_sourced_keys: set[str],
    module: str = "",
    va_int: int | None = None,
    marker: str = "",
    metadata_size: str | None = None,
    metadata_cflags: str | None = None,
) -> None:
    """Warn when metadata-owned keys appear as inline // KEY: comments.

    These keys should live exclusively in rebrew-functions.toml (or rebrew-data.toml
    for DATA/GLOBAL markers).  Inline occurrences are deprecated.

    ``SIZE`` is exempt — ``// SIZE:`` is the reccmp-native contract in the
    ``.c`` (reccmp reads it there) and the TOML value is an override, not a
    migration target.  The only SIZE warning is a disagreement between the
    inline and the metadata value.

    ``CFLAGS`` gets the same treatment for the same reason: an external build
    reads the ``.c``, so an inline value that disagrees with the metadata is
    not a stale copy to delete but two different compiles wearing one name.
    """
    for key, value in found_keys.items():
        if key == "SOURCE" and value.strip().lower() == "naked":
            # The file-borne naked-reconstruction marker written by
            # `rebrew asm --inline-c`: like the // CFLAGS:
            # /DREBREW_ALLOW_NAKED naked-guard convention, it must travel
            # with the file (self-clears when the C body replaces it) —
            # not a metadata-migration candidate.
            continue
        if key == "CFLAGS":
            # An inline copy that differs from the metadata is invisible to
            # every other check: the merge above keeps the inline value in
            # found_keys, and metadata_sourced_keys then suppresses the
            # deprecation warning below.  Report the disagreement instead —
            # `rebrew test`/`verify` compile with the metadata CFLAGS while a
            # build that reads the .c compiles with this one.
            inline_cflags = value.strip()
            if metadata_cflags and codegen_cflags_key(inline_cflags) != codegen_cflags_key(
                metadata_cflags
            ):
                result.warning(
                    result.marker_line,
                    "W019",
                    f"Inline '// CFLAGS: {inline_cflags}' disagrees with metadata "
                    f"CFLAGS '{metadata_cflags}' — a build that reads the .c and "
                    "a tool that reads rebrew-functions.toml compile different "
                    "code; align them",
                )
                continue
        if key == "SIZE":
            inline_size = value.strip()
            agrees = True
            if metadata_size:
                # Compare numerically when both parse: E008 blesses hex
                # spellings (`size = "0x20"`), so a textual compare warned
                # about `// SIZE: 32` vs metadata `0x20` being equal.
                try:
                    agrees = int(inline_size, 0) == int(metadata_size, 0)
                except ValueError:
                    agrees = inline_size == metadata_size
            if metadata_size and not agrees:
                result.warning(
                    result.marker_line,
                    "W019",
                    f"Inline '// SIZE: {value.strip()}' disagrees with "
                    f"metadata SIZE {metadata_size} — the compile contract is "
                    "ambiguous; align them",
                )
            continue
        if key in METADATA_KEYS and key not in metadata_sourced_keys:
            result.warning(
                result.marker_line,
                "W019",
                f"Inline '// {key}:' is deprecated — use rebrew-functions.toml instead",
            )
            # Record for --fix migration (marker type routes the write to the
            # function vs data metadata store).  A table-typed field (LOCALS,
            # COMMENTS, PROVE_CONSTRAINTS) cannot be built from an inline
            # scalar, so --fix must not try — `update_field` rejects the string
            # and the traceback escaped the CLI.
            if module and va_int is not None and not is_table_field(key):
                result._inline_fixes.append((module, va_int, key, value, marker))


def _check_E023_naked_asm(
    result: LintResult,
    lines: list[str],
    code_lines: list[str],
    claimed_statuses: set[str] | None = None,
    metadata_cflags: str = "",
) -> None:
    """Flag whole-function ``__declspec(naked)`` + ``__asm`` dumps (E023).

    *code_lines* is the shared ``_strip_all`` view of *lines*; the raw
    *lines* are still read by the padding checks below, which inspect
    literal source text.

    ``__declspec(naked)`` is only allowed for *minor padding* (1-2 alignment
    ``nop``/``int3`` bytes, e.g. ``_emit 0x90`` / ``_emit 0xCC`` or
    ``__asm nop``).  A whole-function naked body pasted from disassembly is
    not a decompilation and must be flagged as an error.

    Heuristic: a naked function whose asm body exceeds minor padding — more
    than 2 ``__asm``/``_emit`` lines, or any ``_emit`` byte that is not
    padding (``0x90``/``0xCC``) / non-nop mnemonic — is a whole-function
    dump and earns E023.  1-2 nops for alignment are tolerated silently.
    """
    # The project's byte-identity guard: a naked body gated by
    # ``REBREW_ALLOW_NAKED`` — either fenced in ``#ifdef REBREW_ALLOW_NAKED``
    # (with a C fallback in ``#else``) or compiled via ``cflags`` carrying
    # ``/DREBREW_ALLOW_NAKED`` (in rebrew-functions.toml, or a remaining
    # inline ``// CFLAGS:`` annotation) — is the documented workflow for
    # reproducing a compiler whose codegen the available toolchains cannot
    # emit (see AGENTS.md / the naked-guard convention).  That is
    # intentional, not a decompilation shortcut — the flag marks it.
    # Skip E023 for naked bodies gated by REBREW_ALLOW_NAKED.
    if "REBREW_ALLOW_NAKED" in metadata_cflags:
        return
    # Scan the stripped CODE view, not raw lines: a commented-out mention
    # of the guard (a // todo) would otherwise disable E023 for the file.
    for line in code_lines:
        if "REBREW_ALLOW_NAKED" in line:
            return

    # Find the naked declaration in CODE.  The naive
    # `startswith("//")/"/*"/"*"` filter let the interior of a block comment
    # through (a commented-out body whose lines lack a leading `*`), reporting
    # a naked declaration that is not in the source at all.
    has_naked = False
    naked_line = 0
    for idx, code in enumerate(code_lines, start=1):
        if "__declspec(naked)" in code or "__declspec( naked" in code:
            has_naked = True
            naked_line = idx
            break
    if not has_naked:
        return

    emit_lines: list[int] = []
    meaningful_asm: list[int] = []
    for idx, code in enumerate(code_lines, start=1):
        # Scan the stripped CODE view, not raw lines: a block comment's
        # interior lines need not start with `*`, so a commented-out body
        # was counted as an asm dump.
        # Use "_emit" so both "_emit" and "__emit" variants are caught.
        has_asm = "__asm" in code
        has_emit = "_emit" in code
        if has_asm:
            payload = code.lower().split("__asm", 1)[1]
            payload = payload.replace("{", "").replace("}", "").replace(";", "").strip()
            # Only count as meaningful if it carries a mnemonic, not just braces.
            if payload:
                # Strip _emit payload — the emit line itself is counted via emit_lines.
                payload_no_emit = payload.replace("_emit", "").strip()
                # After removing _emit, if nothing left (or just hex) it's not a separate asm mnemonic.
                if (
                    payload_no_emit
                    and payload_no_emit not in ("", ",", "0x90", "0xcc", "0x90,")
                    and not all(
                        tok.strip() in ("", "0x90", "0xcc", ",")
                        for tok in payload_no_emit.replace(",", " , ").split()
                    )
                ):
                    meaningful_asm.append(idx)
        if has_emit:
            emit_lines.append(idx)

    total_meaningful = len(emit_lines) + len(meaningful_asm)
    if total_meaningful == 0:
        return

    # Minor padding allowance: 1-2 meaningful asm/emit lines that are *only*
    # padding (nop / 0x90 / 0xCC / int 3) are tolerated.  Bare `__asm {` /
    # `}` braces are structural and not counted.
    if total_meaningful <= 2:
        padding_only = True
        for idx in meaningful_asm:
            low = lines[idx - 1].lower()
            if "__asm" in low:
                payload = low.split("__asm", 1)[1]
                payload = payload.replace("{", "").replace("}", "").replace(";", "").strip()
                if payload and payload not in ("nop", "int 3", "") and "nop" not in payload:
                    padding_only = False
                    break
        for idx in emit_lines:
            low = lines[idx - 1].lower()
            if "0x90" not in low and "0xcc" not in low and "nop" not in low:
                padding_only = False
                break
        if padding_only:
            return

    claimed = sorted((claimed_statuses or set()) - _UNCLAIMED_STATUSES)
    suffix = f" but STATUS claims {', '.join(claimed)}" if claimed else ""
    result.error(
        naked_line,
        "E023",
        f"whole-function __declspec(naked) + __asm/__emit is not allowed{suffix} — "
        "naked asm is only for minor padding (1-2 alignment bytes: nop / _emit 0x90 / 0xCC); "
        "decompile the function to C instead",
    )


def _check_W020_asm_dump(
    result: LintResult,
    code_lines: list[str],
    claimed_statuses: set[str] | None = None,
    has_blocker: bool = False,
) -> None:
    """Flag asm-dump placeholder implementations (W020).

    Non-naked ``__asm``/``__emit`` bodies are pasted disassembly, not real C
    source.  Whole-function ``__declspec(naked)`` + ``__asm`` is escalated to
    E023 (error); this warning covers the remaining non-naked asm dumps.
    Warn once per file at the first hit.

    Status-aware: a file whose metadata claims a non-stub status
    (``EXACT``/``RELOC``/...) while its body is an asm dump escalates the
    warning — an asm dump cannot be a byte-match, so the STATUS is wrong.
    That is how "documented STUB" (expected) is told apart from a "claimed
    match on an asm dump" (a metadata bug) at a glance.

    A recorded ``BLOCKER`` is the remedy the escalated message names, so an
    asm body under one is documented and not reported at all.  Measured on a
    project where three partial block-fill ``__asm`` bodies sit inside
    functions that do byte-match (RELOC) and carry blockers: the rule fired on
    all three, and its advice could not clear them.
    """
    if has_blocker:
        return
    # Whole-function naked asm is handled by E023 — don't double-report W020.
    # Scan CODE, not raw lines: a block comment's interior lines need not start
    # with `*`, and counting them reported an asm dump that is only commented out.
    for code in code_lines:
        if "__declspec(naked)" in code:
            return
    claimed = sorted((claimed_statuses or set()) - _UNCLAIMED_STATUSES)
    for i, code in enumerate(code_lines, start=1):
        # "_emit", not "__emit": `rebrew asm` writes the bare spelling, so
        # matching only the old prefixed form missed every dump it produced.
        if "_emit" in code:
            if claimed:
                result.warning(
                    i,
                    "W020",
                    f"_emit byte dump but STATUS claims {', '.join(claimed)} — an asm "
                    "placeholder cannot be a byte-match; fix the STATUS or mark BLOCKER",
                )
            else:
                result.warning(
                    i,
                    "W020",
                    "_emit byte dump — function is an asm placeholder, not real C "
                    "source; rewrite it as C (or mark it STUB/BLOCKER with a note)",
                )
            return
        if "__asm" in code:
            if claimed:
                result.warning(
                    i,
                    "W020",
                    f"inline __asm block but STATUS claims {', '.join(claimed)} — an asm "
                    "dump cannot be a byte-match; fix the STATUS or mark BLOCKER",
                )
            else:
                result.warning(
                    i,
                    "W020",
                    "inline __asm block — asm-dump placeholder instead of real C "
                    "source; rewrite the function as C where possible",
                )
            return


def _check_W021_duplicate_globals(
    result: LintResult,
    lines: list[str],
    filepath: Path,
    seen_globals: dict[str, str] | None,
) -> None:
    """Warn when a DATA/GLOBAL symbol name is annotated in multiple files.

    Catches the np-rebrew pattern where ``globals.c`` and another source both
    annotate/define the same global (g_ vs DAT_ collisions, duplicate
    definitions).  ``seen_globals`` maps ``marker:name`` → filepath, threaded
    across the batch like ``seen_vas``.

    The key carries the annotation's marker: a shared tree annotates the same
    symbol once per target (SERVER ``g_log_newline`` at 0x100270e4, the
    client's at 0x677ac8), and those are two binaries' globals, not a
    collision.  Two files annotating one name under the SAME marker still warn.
    """
    if seen_globals is None:
        return
    pending = False
    marker = ""
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        ds_match = _DATA_MARKER_RE.match(s)
        if ds_match:
            pending = True
            marker = f"{ds_match.group(1)}:{ds_match.group(2)}"
            continue
        if not pending:
            continue
        if not s or _is_comment_line(s):
            continue  # comment/blank lines inside the block
        pending = False
        m = _GLOBAL_NAME_RE.search(s)
        if m:
            name = m.group(1)
            key = f"{marker}:{name}"
            prev = seen_globals.get(key)
            if prev is not None and prev != str(filepath):
                result.warning(
                    i,
                    "W021",
                    f"global '{name}' ({marker}) is also annotated in {prev} — "
                    "duplicate definition or naming collision",
                )
            else:
                seen_globals[key] = str(filepath)


_ZERO_INIT_RE = re.compile(
    r"^\s*(?:extern\s+|static\s+)?(?:unsigned\s+|signed\s+|const\s+)?"
    r"[A-Za-z_][\w\s\*]*?\s+[A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*=\s*\{?\s*0\s*\}?\s*;"
)

_GLOBAL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?[;=]")


# Event scanning for _strip_c_comments_strings: the characters that can change
# state, per state.  Ordinary runs between events are copied as bulk slices;
# the per-character loop this replaced was ~70% of batch-lint CPU.
_STRIP_CODE_RE = re.compile(r"""["'/]""")
_STRIP_BLOCK_RE = re.compile(r"\*/")
_STRIP_STR_RE = re.compile(r"""[\\"]""")
_STRIP_CHR_RE = re.compile(r"""[\\']""")
_STRIP_CODE, _STRIP_BLOCK, _STRIP_STR, _STRIP_CHR = range(4)


def _strip_c_comments_strings(line: str, in_block_comment: bool) -> tuple[str, bool]:
    """Remove C comments and string/char literals from *line*.

    Stateful: *in_block_comment* tracks a ``/* ... */`` block spanning
    lines (e.g. a multi-line file preamble).  Quote-aware — ``/*``/``*/``
    inside string or char literals are not comment delimiters, and ``//``
    line comments terminate the rest of the line.  Returns
    ``(cleaned, new_block_state)``; literal contents become spaces so they
    never match code patterns.
    """
    # Fast path: outside a block comment, a line without `"`, `'` or `/`
    # cannot open or close a comment or literal — return it untouched.
    if not in_block_comment and '"' not in line and "'" not in line and "/" not in line:
        return line, False
    out: list[str] = []
    i = 0
    n = len(line)
    state = _STRIP_BLOCK if in_block_comment else _STRIP_CODE
    while i < n:
        if state == _STRIP_BLOCK:
            m = _STRIP_BLOCK_RE.search(line, i)
            if m is None:
                i = n  # rest of the line stays inside the block comment
            else:
                i = m.end()
                state = _STRIP_CODE
            continue
        if state in (_STRIP_STR, _STRIP_CHR):
            # Literal: ordinary chars and the closing quote become one space
            # each; a backslash escape (and the char it escapes) emits
            # nothing — the oracle's exact behaviour, quirks included.
            special = _STRIP_STR_RE if state == _STRIP_STR else _STRIP_CHR_RE
            start = i
            while True:
                m = special.search(line, i) if i < n else None
                if m is None:
                    out.append(" " * (n - start))  # unterminated at EOL
                    i = n
                    break
                pos = m.start()
                if line[pos] == "\\":
                    out.append(" " * (pos - start))
                    i = pos + 2
                    start = i
                    continue
                out.append(" " * (pos - start + 1))  # run + closing quote
                i = pos + 1
                state = _STRIP_CODE
                break
            continue
        # state == _STRIP_CODE
        m = _STRIP_CODE_RE.search(line, i)
        if m is None:
            out.append(line[i:])
            break
        pos = m.start()
        c = line[pos]
        out.append(line[i:pos])
        if c == "/":
            nxt = line[pos + 1] if pos + 1 < n else ""
            if nxt == "*":
                i = pos + 2
                state = _STRIP_BLOCK
                continue
            if nxt == "/":
                break  # line comment — rest of the line is not code
            out.append("/")
            i = pos + 1
            continue
        out.append(" ")  # opening quote of a string/char literal
        i = pos + 1
        state = _STRIP_STR if c == '"' else _STRIP_CHR
    return "".join(out), state == _STRIP_BLOCK


def _strip_all(lines: list[str]) -> list[str]:
    """Return the comment/string-stripped *code view* of every line.

    One stateful pass over the whole file.  E023, W020 and W022 read this
    shared view instead of each re-stripping every line themselves —
    previously four full strip passes per file on the batch-lint hot path.
    """
    out: list[str] = []
    in_block = False
    for line in lines:
        code, in_block = _strip_c_comments_strings(line, in_block)
        out.append(code)
    return out


def _check_W022_zero_init_bss(
    result: LintResult, code_lines: list[str], data_section_names: frozenset[str] = frozenset()
) -> None:
    """Flag file-scope zero initializers (W022).

    A file-scope ``= {0}`` / ``= 0`` forces the global into ``.data``
    (initialized) instead of ``.bss`` (uninitialized, virtual-only) — this
    is exactly the np-rebrew .data bloat (41K of zero-init arrays).  Leave
    the global uninitialized for .bss.

    Exception: a global whose name appears in ``rebrew-data.toml`` with
    ``section = ".data"`` or ``section = ".bss"`` (passed via
    *data_section_names*). A recorded ``.data`` zero-init is in the original
    image. A recorded ``.bss`` ``= 0`` is a placement pin: dropping it moves
    the symbol and rewrites absolute pointers stored in raw ``.data``.
    Untracked ``= 0`` still warns.
    """
    depth = 0
    for i, cleaned in enumerate(code_lines, start=1):
        depth += cleaned.count("{") - cleaned.count("}")
        if depth == 0 and _ZERO_INIT_RE.match(cleaned.strip()):
            if data_section_names:
                name_match = _GLOBAL_NAME_RE.search(cleaned)
                if name_match and name_match.group(1) in data_section_names:
                    continue
            result.warning(
                i,
                "W022",
                "file-scope zero initializer (= {0} / = 0) puts the global in "
                ".data, not .bss — leave it uninitialized to keep the PE small",
            )


def _check_W023_default_func_names(result: LintResult, lines: list[str], pedantic: bool) -> None:
    """Warn about functions with default names (W023) when --pedantic is used.

    Looks for function names that match common default patterns from decompilers
    like fcn, fn, fun, FUN_<addr>, sub_<addr>, etc.
    """
    if not pedantic:
        return

    # Join lines and remove comments/strings to avoid false positives
    code = "\n".join(lines)
    # Simple comment/string removal (not perfect but good enough for this check)
    # Remove /* ... */ comments
    while True:
        start = code.find("/*")
        end = code.find("*/", start + 2)
        if start == -1 or end == -1:
            break
        code = code[:start] + code[end + 2 :]
    # Remove // comments
    code_lines = []
    for line in code.splitlines():
        comment_pos = line.find("//")
        if comment_pos != -1:
            line = line[:comment_pos]
        code_lines.append(line)
    code = "\n".join(code_lines)

    # Look for function definitions with default names
    # Pattern: return_type function_name(...) {

    # Matches are monotonic, so count newlines incrementally — rescanning
    # the whole prefix per match is quadratic on merged multi-function files.
    last_pos = 0
    line_num = 1
    for match in _FUNC_DEF_STYLE_RE.finditer(code):
        func_name = match.group(2)
        line_num += code.count("\n", last_pos, match.start())
        last_pos = match.start()

        # Check against default patterns
        for pattern in DEFAULT_FUNC_NAME_PATTERNS:
            if pattern.fullmatch(func_name):
                result.warning(
                    line_num,
                    "W023",
                    f"Function '{func_name}' has a default name; consider renaming to something meaningful",
                )
                break


_SNAKE_CASE_RE = re.compile(r"[a-z_][a-z0-9_]*")
_CAMEL_CASE_RE = re.compile(r"[a-z][a-zA-Z0-9]*")


def _check_style_rules(result: LintResult, cfg: ProjectConfig | None) -> None:
    """Check code style rules from project config (W024-W027).

    Config keys (all optional, from ``rebrew-project.toml [project.lint]``):
    ``naming_convention`` (snake_case|camelCase|none), ``brace_style``
    (same_line|new_line|none), ``indent_style`` (spaces|tabs|none),
    ``max_line_length``.  Read defensively via ``getattr`` so mocks and
    configs without a ``[project.lint]`` section default to "no rule".
    Unknown enum values are rejected at config load (fall back to ``none``).
    """
    if cfg is None:
        return
    lines = result._lines

    # Naming convention (W024): function definitions should follow the rule.
    naming = getattr(cfg, "lint_naming_convention", "none")
    if naming != "none":
        for i, line in enumerate(lines, start=1):
            m = _FUNC_DEF_STYLE_RE.search(line)
            if not m:
                continue
            func_name = m.group(2)
            if naming == "snake_case" and not _SNAKE_CASE_RE.fullmatch(func_name):
                result.warning(i, "W024", f"Function '{func_name}' should be snake_case")
            elif naming == "camelCase" and not _CAMEL_CASE_RE.fullmatch(func_name):
                result.warning(i, "W024", f"Function '{func_name}' should be camelCase")

    # Brace style (W025).
    brace = getattr(cfg, "lint_brace_style", "none")
    if brace != "none":
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if brace == "new_line" and stripped.endswith("{") and not stripped.startswith("{"):
                result.warning(i, "W025", "Opening brace should be on new line")
            elif brace == "same_line" and stripped == "{":
                result.warning(
                    i, "W025", "Opening brace should be on same line as preceding statement"
                )

    # Indent style (W026).
    indent = getattr(cfg, "lint_indent_style", "none")
    if indent != "none":
        if indent == "spaces":
            for i, line in enumerate(lines, start=1):
                if line.startswith("\t"):
                    result.warning(i, "W026", "Line uses tab indent, expected spaces")
        elif indent == "tabs":
            for i, line in enumerate(lines, start=1):
                if line.startswith(" "):
                    result.warning(i, "W026", "Line uses space indent, expected tabs")

    # Max line length (W027).
    max_len = getattr(cfg, "lint_max_line_length", DEFAULT_LINT_MAX_LINE_LENGTH)
    if max_len and max_len > 0:
        for i, line in enumerate(lines, start=1):
            if len(line) > max_len:
                result.warning(i, "W027", f"Line too long ({len(line)} > {max_len})")


_SUPPORT_MARKER_RE = re.compile(r"//\s*SUPPORT:\s*(\S+)(?:\s+(.*))?")
_STRUCT_BRACE_RE = re.compile(r"\bstruct\s+\w+\s*\{")

#: TOML field name -> uppercase ``found_keys`` name.
_METADATA_TO_FOUND: dict[str, str] = {
    "status": "STATUS",
    "size": "SIZE",
    "cflags": "CFLAGS",
    "toolchain": "TOOLCHAIN",
    "blocker": "BLOCKER",
    "blocker_delta": "BLOCKER_DELTA",
    "ghidra": "GHIDRA",
    "analysis": "ANALYSIS",
    "note": "NOTE",
    "skip": "SKIP",
    "globals": "GLOBALS",
    "locals": "LOCALS",
    "comments": "COMMENTS",
    "section": "SECTION",
    "source": "SOURCE",
}


def support_declaration(lines: list[str]) -> tuple[int, str, str] | None:
    """Return ``(line_no, module, reason)`` for a ``// SUPPORT:`` declaration, or None.

    A support TU exists purely for link reasons (linker-forced shims, CRT
    guard stubs, BSS pads) and has no binary VA of its own to anchor a
    FUNCTION/LIBRARY/STUB/GLOBAL/DATA marker to.  The declaration is a
    single ``// SUPPORT: <MODULE> <reason>`` comment line, e.g.
    ``// SUPPORT: SERVER linker shims keep LIBCMT sbheap.obj out of the link``.
    Only the first such line counts; it must precede any code.
    """
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        m = _SUPPORT_MARKER_RE.match(stripped)
        if m:
            return idx, m.group(1), (m.group(2) or "").strip()
        if stripped.startswith(("//", "/*", "*")):
            continue
        return None
    return None


def _check_body_rules(result: LintResult, lines: list[str], has_new: bool) -> None:
    """Check struct SIZE comments and code presence (W003, W007)."""
    has_code = False
    has_struct = False
    first_struct_line = 1
    struct_has_size = False
    for i, line in enumerate(lines[1:], start=2):
        stripped = line.strip()
        if (
            stripped
            and not stripped.startswith("//")
            and not stripped.startswith("/*")
            and not stripped.startswith("*")
        ):
            has_code = True
        # Guard the struct regex with its literal substring: every match
        # contains "struct", and the search ran on all ~140k lines of a
        # 400-file batch before this (second-hottest lint rule).
        if (
            "struct" in stripped
            and ("typedef struct" in stripped or _STRUCT_BRACE_RE.search(stripped))
            and not stripped.startswith("//")
            and not stripped.startswith("/*")
            and not stripped.startswith("*")
        ):
            if not has_struct:
                first_struct_line = i
            has_struct = True
        if not struct_has_size and _SIZE_ANNOTATION_RE.match(stripped):
            struct_has_size = True

    if not has_code and has_new:
        result.warning(1, "W003", "File has no function implementation")

    if has_struct and not struct_has_size:
        result.warning(
            first_struct_line,
            "W007",
            "File defines struct(s) without // SIZE 0xNN marker (reccmp recommendation)",
        )


#: W022 exemption set per loaded data-metadata document, and the document
#: itself pinned so a freed entry's ``id`` is never reused as a live key.
_DATA_SECTION_NAMES: dict[int, frozenset[str]] = {}
_DATA_SECTION_NAMES_OWNER: dict[int, dict[tuple[str, int], dict[str, Any]]] = {}
_DATA_SECTION_NAMES_MAX = 4
# The owner hit, the two eviction clears, and the two stores are one
# check-then-act over two parallel dicts — the same discipline as
# ``annotation._metadata_file_index``.  Held only for the dict work; the name
# set is built outside it.
_DATA_SECTION_NAMES_LOCK = threading.Lock()


def _data_section_names_for(entries: dict[tuple[str, int], dict[str, Any]]) -> frozenset[str]:
    """The ``.data``-section global names in *entries*, memoized per document.

    ``lint_file`` runs once per source file over a document that the batch
    driver already preloaded once, so rebuilding this set per file re-walked
    every ``rebrew-data.toml`` entry for every file in the tree.
    """
    key = id(entries)
    with _DATA_SECTION_NAMES_LOCK:
        # The eviction below clears both dicts, so a concurrent clear between
        # the owner check and the index read loses the entry: rebuild instead
        # of a KeyError.
        if _DATA_SECTION_NAMES_OWNER.get(key) is entries:
            cached = _DATA_SECTION_NAMES.get(key)
            if cached is not None:
                return cached
    names = frozenset(
        str(entry["name"])
        for entry in entries.values()
        if entry.get("section") in (".data", ".bss") and entry.get("name")
    )
    with _DATA_SECTION_NAMES_LOCK:
        if len(_DATA_SECTION_NAMES) >= _DATA_SECTION_NAMES_MAX:
            _DATA_SECTION_NAMES.clear()
            _DATA_SECTION_NAMES_OWNER.clear()
        _DATA_SECTION_NAMES[key] = names
        _DATA_SECTION_NAMES_OWNER[key] = entries
    return names


def lint_file(
    filepath: Path,
    cfg: ProjectConfig | None = None,
    *,
    seen_vas: dict[Any, str] | None = None,
    seen_va_defines: dict[Any, bool] | None = None,
    seen_globals: dict[str, str] | None = None,
    preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
    preloaded_data_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
    function_index: tuple[set[int], list[tuple[int, int, str]]] | None = None,
    pedantic: bool = False,
    section_for_va: Any = None,
    section_hits: list[MissingSection] | None = None,
) -> LintResult:
    """Lint a single C file.

    Args:
        filepath: Path to the .c file.
        cfg: Optional ProjectConfig for config-aware checks.
        seen_vas: Optional dict mapping VA → filename for duplicate detection.
                  Will be mutated (VAs from this file are added).
        seen_va_defines: Optional parallel dict mapping the same keys to
                  whether the first-seen block defines its symbol (DATA/
                  GLOBAL E013 needs both sides defining to collide).
        seen_globals: Optional dict mapping global symbol name → filename for
                      W021 duplicate-global detection. Will be mutated.
        preloaded_metadata: Pre-loaded metadata dict (avoids per-file I/O in batch).
        preloaded_data_metadata: Pre-loaded data metadata dict (avoids per-file I/O in batch).
        function_index: ``(starts, spans)`` from the target function list
                        (built once per batch); enables the W028
                        annotation-staleness cross-check.
        section_for_va: Optional callable mapping a VA to its binary section
                        name; enables W016 autofix collection in
                        ``section_hits``.
        section_hits: Optional list collecting :class:`MissingSection` for
                      DATA/GLOBAL markers whose VA resolves to a section.
        pedantic: Enable the pedantic-only W023 (default function name) check.

    """
    result = LintResult(filepath)

    # A caller may pass a shared seen_vas dict for cross-file duplicate
    # detection; with None (single-file lint) duplicate VAs WITHIN this file
    # must still be caught, so fall back to a per-file dict.
    if seen_vas is None:
        seen_vas = {}
    if seen_va_defines is None:
        seen_va_defines = {}

    try:
        text, _ = read_source_text(filepath)
    except OSError as e:
        result.error(0, "E000", f"Cannot read file: {e}")
        return result

    lines = text.splitlines()
    if not lines:
        result.error(1, "E001", "Empty file, missing FUNCTION/LIBRARY/STUB marker")
        return result
    result._lines = lines

    # A support TU declares itself with `// SUPPORT: <MODULE> <reason>` and
    # carries no VA-anchored marker by design.  Blessed here: no E001, and
    # none of the annotation checks below apply (there are no headers to
    # check).  Body rules (W003/W007) still run — a support file with no
    # code at all is dead weight, not support.
    support = support_declaration(lines)
    if support is not None:
        _support_line, _support_module, _support_reason = support
        if not _support_reason:
            result.error(
                _support_line, "E001", "// SUPPORT: needs a reason (what breaks without this file)"
            )
            return result
        result._marker_counts["SUPPORT"] += 1
        _check_body_rules(result, lines, True)
        return result
    all_headers = _parse_multi_headers(lines)
    if not all_headers:
        # Totally broken file — no recognisable marker format found.
        # Synthesise a minimal entry so the loop below can report E001.
        all_headers = [({}, {"has_new": False})]
    result._headers = all_headers

    # Load per-directory metadata (keys: (module, va_int) -> {toml_field: value}).
    # Accept pre-loaded dicts from callers that process many files in the same directory
    # (avoids repeated I/O for the common batch-lint case).
    # metadata_dir walks the tree upward per access, so resolve it only when a
    # preload does not already answer for this directory.
    _metadata_dir = (
        None
        if preloaded_metadata is not None and preloaded_data_metadata is not None
        else (cfg.metadata_dir if cfg else filepath.parent)
    )
    _metadata_entries = (
        preloaded_metadata
        if preloaded_metadata is not None
        else load_metadata(_metadata_dir, deepcopy=False)
    )
    _data_metadata_entries = (
        preloaded_data_metadata
        if preloaded_data_metadata is not None
        else load_data_metadata(_metadata_dir)
    )

    # Marker keys this project recognises, folded once per file: the NFC +
    # upper of every marker in cfg.all_markers is per-annotation work below
    # otherwise, on a tree with thousands of annotated blocks.
    _own_marker = getattr(cfg, "marker", None) if cfg is not None else None
    _known_markers = getattr(cfg, "all_markers", None) or (
        {_own_marker} if _own_marker else set()
    )
    _known_folded = {preset_module_key(str(item)) for item in _known_markers if item}

    # Statuses claimed by this file's annotations (for W020 escalation: a
    # non-STUB claim on an asm-dump body is a metadata error).
    _file_statuses: set[str] = set()
    # A recorded BLOCKER documents why the body is what it is; W020's own text
    # tells the author to add one, so an asm block under a blocker is the
    # documented end state, not a placeholder to flag.
    _file_has_blocker = False
    # CFLAGS from metadata/inline annotations (for the E023 REBREW_ALLOW_NAKED
    # guard — the flag lives in rebrew-functions.toml, not in source lines).
    _file_cflags: set[str] = set()

    for found_keys, flags in all_headers:
        result.marker_line = int(found_keys.get("_LINE", "1"))

        mod = found_keys.get("MODULE", "")
        va_str = found_keys.get("VA", "")

        # Overlay metadata fields into found_keys for this marker block.
        #
        # SIZE / CFLAGS are co-read (reccmp contract): keep any inline value in
        # found_keys so W019 can report disagreement with the store; equal
        # CFLAGS copies are stripped below, SIZE is never auto-stripped.
        #
        # Every other metadata-owned key (STATUS, NOTE, BLOCKER, …) has the
        # store as sole source of truth — annotation parsing ignores the
        # inline form — so checks must see the TOML value.  Equal inline
        # copies are stripped; disagreements warn (W019) and leave the inline
        # text for the author (never migrate inline → store, which would
        # clobber a promoted STATUS with a stale // STATUS: STUB).
        #
        # Track which keys the store supplied so W019 can tell a key that
        # must be migrated from one that is correctly metadata-only.
        _metadata_sourced_keys: set[str] = set()
        _va_int: int | None = None
        _metadata_size: str | None = None
        _metadata_override: dict[str, Any] = {}
        # Keys co-read from the .c (inline kept in found_keys for W019).
        _coread_keys = frozenset({"SIZE", "CFLAGS"})
        if mod and va_str:
            try:
                _va_int = int(va_str, 16)
                _metadata_override = _metadata_entries.get((mod, _va_int), {})
                _metadata_size = str(_metadata_override.get("size", "")).strip() or None
                for _toml_key, _found_key in _METADATA_TO_FOUND.items():
                    if _toml_key not in _metadata_override:
                        continue
                    store_val = str(_metadata_override[_toml_key])
                    if _found_key not in found_keys:
                        found_keys[_found_key] = store_val
                    elif _found_key in _coread_keys:
                        # Co-read: leave inline in found_keys; W019 handles
                        # disagreement.  Equal CFLAGS still strip below.
                        if _found_key == "CFLAGS" and inline_equals_store(
                            _found_key, found_keys[_found_key], store_val
                        ):
                            result._inline_dup_strips.append((mod, _va_int, _found_key))
                    elif inline_equals_store(_found_key, found_keys[_found_key], store_val):
                        # Dead duplicate of the store value — strip on --fix.
                        result._inline_dup_strips.append((mod, _va_int, _found_key))
                        found_keys[_found_key] = store_val
                    else:
                        # Disagreement: store wins for E015/E017/…; warn and
                        # leave the inline so --fix cannot clobber the store.
                        inline_val = found_keys[_found_key].strip()
                        result.warning(
                            result.marker_line,
                            "W019",
                            f"Inline '// {_found_key}: {inline_val}' disagrees with "
                            f"metadata {_found_key} '{store_val}' — "
                            "rebrew-functions.toml is the source of truth; "
                            "align or remove the inline copy",
                        )
                        found_keys[_found_key] = store_val
                    _metadata_sourced_keys.add(_found_key)
            except (ValueError, KeyError) as exc:
                # A malformed inline block drops the key from the drift
                # comparison, so a disagreeing SIZE would go unreported.
                log.debug("unreadable inline metadata at %s: %s", result.marker_line, exc)

        ctx = f"[{mod} {va_str}] " if mod and va_str else ""

        if len(all_headers) > 1:
            result.context_prefix = ctx
        else:
            result.context_prefix = ""

        if not _check_format_errors(result, flags):
            continue

        if flags["has_new"]:
            marker = found_keys.get("MARKER", "")
            _check_E001_marker(result, marker)

            va_int = _check_E002_va(
                result, va_str, min_va=min_valid_va_for(cfg) if cfg else MIN_VALID_VA
            )

            # Check EVERY block of a multi-function file, keyed on
            # (module, va) so a multi-module file whose blocks share a VA
            # (a valid layout) is not flagged.
            # DATA/GLOBAL also pass the marker kind + body so the check can
            # tell a second definition (real collision) from an extern/bare
            # claim beside the single definition (progressive ownership).
            _check_E013_duplicate_va(
                result,
                va_int,
                va_str,
                filepath,
                seen_vas,
                module=mod,
                marker=marker,
                lines=lines,
                marker_line=result.marker_line,
                seen_va_defines=seen_va_defines,
            )

            if marker in ("FUNCTION", "STUB") and va_int is not None:
                _check_W028_stale_annotation(
                    result,
                    va_int,
                    mod,
                    cfg,
                    function_index,
                    # Store-wins overlay (above): an EXACT/RELOC in
                    # rebrew-functions.toml suppresses W028 even when a stale
                    # inline // STATUS: STUB remains.
                    status=canonical_status(str(found_keys.get("STATUS", ""))),
                    metadata=_metadata_entries,
                )

            if marker not in DATA_MARKERS:
                # A stacked shared-source block for ANOTHER target answers to
                # its own target's defaults, not this one's — flagging it for
                # missing CFLAGS here is misattribution (ADR-010).
                _own_key = preset_module_key(_own_marker) if _own_marker else ""
                _mod_key = preset_module_key(mod) if mod else ""
                if not (
                    cfg is not None
                    and _own_marker
                    and mod
                    and _mod_key != _own_key
                    and _mod_key in _known_folded
                ):
                    _check_W018_cflags(result, found_keys, cfg)
            # For DATA/GLOBAL: overlay data metadata fields (size, section, note).
            # SIZE is co-read; SECTION/NOTE follow the same store-wins rule
            # as function metadata above.
            elif va_int is not None and mod:
                _ds_override = _data_metadata_entries.get((mod, va_int), {})
                # A data symbol's SIZE lives in rebrew-data.toml, so W019 must
                # compare the inline copy against THAT store. Left at the
                # function-store value it saw, a DATA/GLOBAL block reported a
                # disagreement against a size it never read, and the
                # already-migrated hint from `_w019_key_backed` suppressed
                # the very warning that would have shown it.
                if "size" in _ds_override:
                    _metadata_size = str(_ds_override["size"]).strip() or None
                _DS_TO_FOUND = {"size": "SIZE", "section": "SECTION", "note": "NOTE"}
                for _ds_key, _ds_found_key in _DS_TO_FOUND.items():
                    if _ds_key not in _ds_override:
                        continue
                    store_val = str(_ds_override[_ds_key])
                    if _ds_found_key not in found_keys:
                        found_keys[_ds_found_key] = store_val
                    elif _ds_found_key == "SIZE":
                        pass  # co-read; W019 reports disagreement
                    elif inline_equals_store(_ds_found_key, found_keys[_ds_found_key], store_val):
                        result._inline_dup_strips.append((mod, va_int, _ds_found_key))
                        found_keys[_ds_found_key] = store_val
                    else:
                        inline_val = found_keys[_ds_found_key].strip()
                        result.warning(
                            result.marker_line,
                            "W019",
                            f"Inline '// {_ds_found_key}: {inline_val}' disagrees "
                            f"with metadata {_ds_found_key} '{store_val}' — "
                            "rebrew-data.toml is the source of truth; "
                            "align or remove the inline copy",
                        )
                        found_keys[_ds_found_key] = store_val
                    _metadata_sourced_keys.add(_ds_found_key)

            module = found_keys.get("MODULE", "")
            # Canonicalize so hand-edited `status = "exact"` / `// STATUS: stub`
            # feed E015/E017/MATCHED_STATUSES the same way update_source_status does.
            status = canonical_status(found_keys.get("STATUS", ""))
            _file_cflags.update(found_keys.get("CFLAGS", "").split())
            if found_keys.get("BLOCKER"):
                _file_has_blocker = True

            # Collect summary data during the lint pass (used by _print_summary).
            if marker:
                result._marker_counts[marker] += 1
            if status:
                result._status_counts[status] += 1
                _file_statuses.add(status)

            _check_E015_marker_consistency(result, marker, module, status, cfg)
            _check_W005_blocker(result, status, found_keys)
            _check_W006_source(result, module, found_keys, cfg)
            _check_W010_unknown_keys(result, found_keys, module=mod, va_int=_va_int)
            _check_E017_contradictory(result, status, marker)
            _check_E004_status_value(result, status)
            _check_E008_size_value(result, _metadata_size)
            _check_config_rules(result, found_keys, cfg)

            _check_W015_va_case(result, va_str)
            _check_W016_section(
                result,
                marker,
                found_keys,
                module=mod,
                va_int=_va_int,
                section_for_va=section_for_va,
                section_hits=section_hits,
            )
            _check_W019_inline_metadata(
                result,
                found_keys,
                _metadata_sourced_keys,
                module=mod,
                va_int=_va_int if mod else None,
                marker=marker,
                metadata_size=_metadata_size,
                metadata_cflags=str(_metadata_override.get("cflags", "") or "").strip() or None,
            )

    result.context_prefix = ""
    # Names of globals annotated section=".data" in rebrew-data.toml — W022
    # exemption (the original binary stored the zero-init data in .data).
    _data_section_names = _data_section_names_for(_data_metadata_entries)
    code_lines = _strip_all(lines)  # one strip pass shared by E023/W020/W022
    _check_E023_naked_asm(result, lines, code_lines, _file_statuses, " ".join(_file_cflags))
    _check_W020_asm_dump(result, code_lines, _file_statuses, _file_has_blocker)
    _check_W021_duplicate_globals(result, lines, filepath, seen_globals)
    _check_W022_zero_init_bss(result, code_lines, _data_section_names)
    _check_body_rules(result, lines, all_headers[0][1]["has_new"] if all_headers else False)
    _check_W023_default_func_names(result, lines, pedantic)
    _check_W030_va_order(result, all_headers, lines)
    _check_style_rules(result, cfg)
    return result


def _print_summary(results: list[LintResult]) -> None:
    """Print a breakdown table by status and marker type.

    Uses counters collected during the lint pass (LintResult._status_counts
    and _marker_counts) instead of re-reading every file.
    """
    status_counts: Counter[str] = Counter()
    marker_counts: Counter[str] = Counter()
    for r in results:
        status_counts += r._status_counts
        marker_counts += r._marker_counts

    console.print()
    table = Table(title="Summary", show_lines=False, pad_edge=False)
    table.add_column("Category", style="bold")
    table.add_column("Value")
    table.add_column("Count", justify="right", width=8, no_wrap=True)

    for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
        table.add_row("STATUS", untrusted_ident(status), str(count))
    for marker, count in sorted(marker_counts.items(), key=lambda x: -x[1]):
        table.add_row("MARKER", marker, str(count))

    console.print(table)


app = typer.Typer(
    help="Lint source marker standards for decomp C source files.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew lint · · · · · · · · · · · · Lint all .c files in reversed_dir\n\n"
        "  rebrew lint --quiet · · · · · · · · Errors only, suppress warnings\n\n"
        "  rebrew lint --json · · · · · · · · · Machine-readable JSON output\n\n"
        "  rebrew lint --summary · · · · · · · Show status/origin breakdown table\n\n"
        "  rebrew lint src/game/foo.c · · · · · Lint specific files only\n\n"
        "  rebrew lint --fix --dry-run · · · · Preview migrations, strips, and backfills before commit\n\n"
        "[bold]Error codes:[/bold]\n\n"
        "  E001   Missing FUNCTION/LIBRARY/STUB marker (or reason-less // SUPPORT:)\n\n"
        "  E002   Invalid VA format or range\n\n"
        "  E012   Module doesn't match configured marker\n\n"
        "  E013   Duplicate VA across files\n\n"
        "  W005   STUB without BLOCKER explanation\n\n"
        "  W016   DATA/GLOBAL missing SECTION metadata\n\n"
        "  W010   Unknown marker key\n\n"
        "  W018   Missing CFLAGS with no config fallback\n\n"
        "  W019   Inline metadata key (STATUS, NOTE, etc.) should be in rebrew-functions.toml\n\n"
        "  W020   Asm-dump placeholder (__emit / __asm block) instead of real C source\n\n"
        "  E023   Whole-function __declspec(naked) + __asm/__emit (only 1-2 nop/0x90/0xCC padding bytes allowed)\n\n"
        "  W021   Duplicate global symbol annotated in multiple files\n\n"
        "  W022   File-scope zero initializer (= {0}) forces the global into .data, not .bss\n"
        '         (exempt: globals annotated section = ".data" in rebrew-data.toml)\n\n'
        "  W023   Function has a default name (fcn, fn, fun, etc.); consider renaming\n\n"
        "  W024   Function name does not match project naming convention\n\n"
        "  W025   Opening brace style does not match project configuration\n\n"
        "  W026   Line indent style does not match project configuration\n\n"
        "  W027   Line too long (exceeds max_line_length)\n\n"
        "  W028   Annotation VA matches no function in the current function list\n"
        "         (stale after a binary update — re-annotate or refresh the list)\n\n"
        "  W029   Redundant cflags — per-function or preset cflags that only repeat\n"
        "         the inherited value (project cflags / module preset) — --fix drops them\n"
        "         (the fallback chain already supplies the same flags)\n\n"
        "  W030   A file's FUNCTION/STUB markers for one module do not ascend by VA\n\n"
        "  W031   Metadata store problem — an unknown field, a STATUS outside the store's\n"
        "         vocabulary, half an updated_by/updated_at pair, an unknown provenance\n"
        "         tag, a stray top-level key, or a missing / foreign format stamp\n\n"
        "  W032   Coverage store hygiene — a leftover artifact from a store rebrew no\n"
        "         longer reads, or a coverage-<target>.toml the dashboards cannot serve\n\n"
        "  W033   Rendered agent instructions have drifted from the packaged skills\n\n"
        "  W034   A stored `file` identity is absolute or escapes the project with '..'\n\n"
        "  W035   A metadata row's module matches no target marker or library module\n"
        "         (invisible to status/todo after a rename)\n\n"
        "[dim]Checks for reccmp-style markers in each .c file, plus project-level\n"
        "corpus hygiene (W029 cflags redundancy, W031-W035 store and scaffold drift).[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    fix: bool = typer.Option(
        False,
        "--fix",
        help=("Migrate inline metadata, strip redundant lines, backfill SECTION (W016)"),
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only show errors, suppress warnings"),
    pedantic: bool = typer.Option(
        False,
        "--pedantic",
        help="Warn on functions that have not been renamed yet to a meaningful name",
    ),
    files: list[Path] | None = typer.Argument(
        None, help="Specific files to check (defaults to all *.c in project)"
    ),
    summary: bool = typer.Option(False, "--summary", help="Print status/origin breakdown"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    all_targets: bool = AllTargetsOption,
) -> None:
    """Lint source marker standards in decomp C source files."""
    all_targets = option_default(all_targets, False)
    if all_targets_run(
        target=target,
        all_targets=all_targets,
        json_mode=json_output,
        run_one=lambda n: main(
            fix=fix,
            dry_run=dry_run,
            quiet=quiet,
            pedantic=pedantic,
            files=files,
            summary=summary,
            json_output=json_output,
            target=n,
            all_targets=False,
        ),
    ):
        return
    # `load_config`, not `require_config`: naming files explicitly lints them
    # without a project (config-aware rules off).  Bare `rebrew lint` has no
    # such fallback — see the `reversed_dir` branch below.
    cfg = None
    no_config = False
    try:
        cfg = load_config(target=target)
    except FileNotFoundError:
        no_config = True
    except (KeyError, ValueError) as exc:
        console.print(
            f"[yellow]warning:[/yellow] config error ({untrusted_ident(exc)}); "
            "config-aware rules disabled"
        )

    reversed_dir = cfg.reversed_dir if cfg else None

    exts = source_exts(cfg)
    if files:
        # `source_ext` may hold several comma-separated extensions; comparing
        # the raw string against `f.suffix` matched nothing, so `rebrew lint
        # foo.cpp` with `source_ext = ".c,.cpp"` silently checked 0 files.
        # Both sides are lowercased: `_parse_source_ext` keeps the configured
        # spelling, and `iter_sources` matches suffixes case-insensitively
        # (sources.files_with_ext), so `rebrew lint FOO.C` with
        # `source_ext = ".C"` must find the same file as a bare run.
        lowered = {ext.lower() for ext in exts}
        c_files = [f for f in files if f.suffix.lower() in lowered]
    elif reversed_dir:
        c_files = iter_sources(reversed_dir, cfg)
    elif no_config:
        # No project and no file list: the only thing left to guess is "every
        # C file under the cwd", which lints vendored trees (.venv, build/)
        # and reports their findings as the project's.  Exit 2 like every
        # other command that cannot find a project, naming both ways out.
        error_exit(
            "no rebrew-project.toml found and no files given. "
            "Run 'rebrew lint' from inside a project, or pass the files to "
            "check explicitly (rebrew lint path/to/file.c).",
            json_mode=json_output,
        )
    else:
        c_files = sorted({p for ext in exts for p in Path.cwd().rglob(f"*{ext}")})

    # Cross-file duplicate tracking: VAs (E013) and global names (W021).
    # seen_vas keys are (module, va) tuples — bare int would falsely flag
    # cross-module files that legitimately share a VA in different targets.
    seen_vas: dict[Any, str] = {}
    seen_va_defines: dict[Any, bool] = {}
    seen_globals: dict[str, str] = {}

    # Pre-load metadata once for the whole batch (avoids per-file I/O).
    _preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None
    _preloaded_data_metadata: dict[tuple[str, int], dict[str, Any]] | None = None
    if cfg:
        _preloaded_metadata = load_metadata(cfg.metadata_dir, deepcopy=False)
        _preloaded_data_metadata = load_data_metadata(cfg.metadata_dir)
    # Pre-load the function list once for the whole batch (W028).
    function_index = _build_function_index(cfg) if cfg else None
    # Section resolver for W016 autofix (DATA/GLOBAL markers missing SECTION):
    # one binary parse per batch, mapping VA -> section name.  The load is
    # deferred to the first VA actually queried: a run without a SECTION-less
    # DATA/GLOBAL marker never pays LIEF's ~0.13 s import, and an unusable
    # binary just leaves the resolver returning "" (W016 stays warn-only).
    section_for_va: Any = None
    if cfg is not None and getattr(cfg, "target_binary", None):
        _bin_path = cfg.target_binary
        _loaded = False
        _ranges: list[tuple[int, int, str]] = []
        _starts: list[int] = []

        def section_for_va(va: int) -> str:
            nonlocal _loaded, _ranges, _starts
            if not _loaded:
                _loaded = True  # an unusable binary must not retry per VA
                try:
                    from rebrew.binary_loader import load_binary

                    _info = load_binary(_bin_path)
                    _ranges = sorted(
                        ((s.va, s.va + s.size, s.name) for s in _info.sections.values()),
                        key=lambda t: t[0],
                    )
                    _starts = [r[0] for r in _ranges]
                except Exception:
                    _ranges = []
                    _starts = []
            idx = bisect.bisect_right(_starts, va) - 1
            # A shorter section nested in a longer one must not hide the outer tail.
            while idx >= 0:
                start, end, name = _ranges[idx]
                if start <= va < end:
                    return name
                idx -= 1
            return ""

    section_hits: list[MissingSection] = []

    total = 0
    passed = 0
    error_count = 0
    warning_count = 0
    all_results: list[LintResult] = []

    display_buf: list[str] = []
    for cfile in c_files:
        total += 1
        result = lint_file(
            cfile,
            cfg=cfg,
            seen_vas=seen_vas,
            seen_va_defines=seen_va_defines,
            seen_globals=seen_globals,
            preloaded_metadata=_preloaded_metadata,
            preloaded_data_metadata=_preloaded_data_metadata,
            function_index=function_index,
            pedantic=pedantic,
            section_for_va=section_for_va,
            section_hits=section_hits,
        )
        all_results.append(result)
        if result.passed:
            passed += 1
        if not json_output and (not result.passed or (not quiet and result.warnings)):
            display_buf.extend(result._display_lines(quiet))
        error_count += len(result.errors)
        warning_count += len(result.warnings)

    if display_buf:
        # One Rich print for the whole batch: nothing else prints during the
        # loop, so the output bytes are identical — one markup+wrap pass
        # instead of ~400 per-file envelopes (the largest remaining lint
        # cost after the W029 batching).
        console.print("\n".join(display_buf), highlight=False)

    # W029: redundant cflags across metadata + presets — batch-level, since
    # no single .c file owns a preset and the redundancy is about the fallback
    # ladder.  Attribute per-function warnings back to the file that hosts the
    # VA when possible; presets and unattributed VAs land on a synthetic entry.
    preset_redundant: list[RedundantPreset] = []
    fn_redundant: list[RedundantFunctionCflags] = []
    if cfg is not None:
        preset_redundant, fn_redundant = check_redundant_cflags(cfg, _preloaded_metadata)
        if preset_redundant or fn_redundant:
            # Build VA -> file index from this run, for per-function attribution.
            # LintResult.marker_line holds the LAST marker in the file, so
            # the header's own line travels with the index.
            va_to_result: dict[tuple[str, int], tuple[LintResult, int]] = {}
            for r in all_results:
                headers = r._headers if r._headers is not None else _parse_multi_headers(r._lines)
                for keys, _flags in headers:
                    m = keys.get("MODULE", "")
                    v = keys.get("VA", "")
                    if not m or not v:
                        continue
                    with contextlib.suppress(ValueError):
                        va_to_result[(m, int(v, 16))] = (r, int(keys.get("_LINE", "1")))
            # Presets: no single file — emit on a synthetic "config" result.
            if preset_redundant:
                syn = LintResult(Path("rebrew-project.toml"))
                for hit in preset_redundant:
                    syn.warning(1, "W029", f"redundant cflags preset: {hit.message()}")
                all_results.append(syn)
                if not json_output and not quiet:
                    syn.display(quiet=False)
                warning_count += len(syn.warnings)
            # Per-function redundancies: attribute per file when we can.
            unattributed: list[RedundantFunctionCflags] = []
            w029_inline: list[str] = []
            for fn_hit in fn_redundant:
                located = va_to_result.get((fn_hit.module, fn_hit.va))
                msg = fn_hit.message()
                if located is not None:
                    dest, line = located
                    if not any(c == "W029" and msg in m for _, c, m in dest.warnings):
                        dest.warning(line, "W029", f"redundant cflags: {msg}")
                        warning_count += 1
                        if not json_output and not quiet:
                            # Show the newly added warnings inline (the batch
                            # loop already printed these files) — collected
                            # and emitted as ONE Rich print below: per-hit
                            # prints were 1600 console calls on a
                            # 400-file tree, ~27% of lint's runtime.
                            w029_inline.append(
                                f"  [bold]{untrusted_ident(dest.filepath.name)}[/bold]:{line}: "
                                f"[yellow]W029[/yellow]: redundant cflags: "
                                f"{untrusted_ident(msg)}"
                            )
                else:
                    unattributed.append(fn_hit)
            if w029_inline:
                console.print("\n".join(w029_inline), highlight=False)
            if unattributed:
                syn2 = LintResult(Path("rebrew-functions.toml"))
                for fn_hit in unattributed:
                    syn2.warning(1, "W029", f"redundant cflags: {fn_hit.message()}")
                all_results.append(syn2)
                if not json_output and not quiet:
                    syn2.display(quiet=False)
                warning_count += len(syn2.warnings)

    # W031 / W032: the same batch-level shape as W029 — no .c file owns the
    # metadata store or the coverage directory, so each finding lands on the
    # artifact it describes and the per-file loop stays untouched.
    if cfg is not None:
        for artifact_result in (
            *_check_W031_metadata_store(cfg),
            *_check_W032_coverage_store(cfg),
            *_check_W036_stray_metadata_store(cfg),
            *_check_W034_identity_paths(cfg),
            *_check_W035_unknown_modules(cfg),
            *_check_W033_agent_scaffold(cfg),
        ):
            all_results.append(artifact_result)
            warning_count += len(artifact_result.warnings)
            if not json_output and not quiet:
                artifact_result.display(quiet=False)

    if json_output:
        # --quiet keeps the counts but lists only failing files, without
        # their warnings (docs: "Suppress warnings, show errors only").
        files_out = [r.to_dict() for r in all_results if not r.passed or (r.warnings and not quiet)]
        if quiet:
            for entry in files_out:
                entry["warnings"] = []
        output = {
            "total": total,
            "passed": passed,
            "errors": error_count,
            "warnings": warning_count,
            "files": files_out,
        }
        json_print(output)
    else:
        pass_style = "green" if error_count == 0 else "red"
        err_style = "red" if error_count > 0 else ""
        result_text = Text()
        result_text.append(f"\nChecked {total} files: ")
        result_text.append(f"{passed} passed", style=pass_style)
        result_text.append(", ")
        result_text.append(f"{error_count} errors", style=err_style)
        result_text.append(f", {warning_count} warnings")
        console.print(result_text)

        if summary:
            _print_summary(all_results)

    # Apply --fix: migrate inline metadata to rebrew-functions.toml /
    # rebrew-data.toml (the destination depends on the marker type).
    # Without a loaded config the migration has nowhere to write — say so
    # instead of silently doing nothing (functionality-review: a user running
    # --fix outside a project saw zero effect and no explanation).
    if fix and not cfg:
        console.print(
            "[yellow]warning:[/yellow] --fix needs a rebrew-project.toml — "
            "no config loaded, nothing migrated"
        )
    if fix and cfg:
        from rebrew.annotation import remove_inline_annotation_key
        from rebrew.compile_overrides import resolve_cflags
        from rebrew.data_metadata import (
            DATA_METADATA_FIELDS,
            DATA_STATUSES,
            get_data_entry,
            set_data_field,
            set_data_fields_batch,
        )
        from rebrew.metadata import (
            coerce_metadata_value,
            get_entry,
            remove_fields_batch,
            update_field,
            update_source_status,
        )

        fix_count = 0
        strip_count = 0
        for r in all_results:
            if r._inline_strips and not dry_run:
                for _module, va, key in r._inline_strips:
                    if remove_inline_annotation_key(r.filepath, va, key):
                        strip_count += 1
            elif r._inline_strips and dry_run:
                for _module, _va, key in r._inline_strips:
                    console.print(
                        f"  [dim]Would strip[/dim] {untrusted_ident(r.filepath.name)} "
                        f"// {untrusted_ident(key)}: (unknown annotation key)"
                    )
                    strip_count += 1
            # Inline copies that duplicate the metadata store with an equal
            # value: silent in the lint pass (no warning — the store owns the
            # field), stripped here so one --fix run converges.
            if r._inline_dup_strips and not dry_run:
                for _module, va, key in r._inline_dup_strips:
                    if remove_inline_annotation_key(r.filepath, va, key):
                        strip_count += 1
            elif r._inline_dup_strips and dry_run:
                for _module, _va, key in r._inline_dup_strips:
                    console.print(
                        f"  [dim]Would strip[/dim] {untrusted_ident(r.filepath.name)} "
                        f"// {untrusted_ident(key)}: (already in metadata)"
                    )
                    strip_count += 1
        # Strips from the migration loop below (legacy keys, redundant inline
        # CFLAGS, already-migrated copies) — counted separately so the
        # summary never reports a pure strip as a "migration".
        inline_strip_count = 0
        for r in all_results:
            if not r._inline_fixes:
                continue
            for module, va, key, value, marker in r._inline_fixes:
                toml_key = key.lower()
                is_data_marker = marker in DATA_MARKERS
                # ORIGIN is legacy everywhere; SECTION is legacy for functions
                # but a real data-metadata field for data markers.
                # Legacy keys are never stored — just strip the inline form.
                if key in ("ORIGIN", "UPDATED_BY", "UPDATED_AT") or (
                    not is_data_marker and key == "SECTION"
                ):
                    if dry_run:
                        console.print(
                            f"  [dim]Would strip[/dim] {untrusted_ident(r.filepath.name)} "
                            f"// {untrusted_ident(key)}: (legacy key — never stored)"
                        )
                        inline_strip_count += 1
                    elif remove_inline_annotation_key(r.filepath, va, key):
                        inline_strip_count += 1
                    continue
                # An inline CFLAGS that only repeats the inherited ladder
                # would migrate into a W029-redundant per-function cflags —
                # strip it without writing.
                if toml_key == "cflags":
                    inherited = resolve_cflags(cfg, None, module)
                    if cflags_key(value.strip()) == cflags_key(inherited):
                        if dry_run:
                            console.print(
                                f"  [dim]Would strip[/dim] {untrusted_ident(r.filepath.name)} "
                                f"// {untrusted_ident(key)}: {value!r} "
                                f"(redundant — inherits {inherited!r})"
                            )
                            inline_strip_count += 1
                        elif remove_inline_annotation_key(r.filepath, va, key):
                            inline_strip_count += 1
                        continue
                # A function-only key (or function STATUS value) on a
                # DATA/GLOBAL marker has no home in rebrew-data.toml: leave it
                # inline (W019 keeps flagging it).
                if is_data_marker and (
                    key not in DATA_METADATA_FIELDS
                    or (key == "STATUS" and value.strip() not in DATA_STATUSES)
                ):
                    console.print(
                        f"  [yellow]Skipped[/yellow] {untrusted_ident(r.filepath.name)} "
                        f"// {untrusted_ident(key)}: (not a data metadata field)"
                    )
                    continue
                if is_data_marker:
                    existing = get_data_entry(cfg.metadata_dir, va, module)
                    present = toml_key in {k.lower() for k in existing}
                else:
                    existing = get_entry(cfg.metadata_dir, va, module)
                    present = toml_key in existing
                if not present:
                    if dry_run:
                        store = "rebrew-data.toml" if is_data_marker else "rebrew-functions.toml"
                        console.print(
                            f"  [dim]Would migrate[/dim] {untrusted_ident(r.filepath.name)} "
                            f"// {untrusted_ident(key)}: {value!r} → {store}"
                        )
                    else:
                        # Coerce size/blocker_delta to int via the shared
                        # metadata facade (single canonical coercion).
                        write_value = coerce_metadata_value(toml_key, value)
                        if is_data_marker:
                            set_data_field(
                                cfg.metadata_dir,
                                va,
                                toml_key,
                                write_value,
                                module=module,
                                updated_by="lint",
                            )
                        elif toml_key == "status":
                            # STATUS must go through the promotion gate
                            # (validates the value, never silently unparks
                            # SKIP).  Clear blockers only for EXACT/RELOC —
                            # migrating // STATUS: NEAR_MATCHING must not erase
                            # an accompanying BLOCKER that this same --fix
                            # pass is about to migrate; PROVEN keeps blockers
                            # for the same reason as rebrew prove.
                            canon = canonical_status(str(write_value))
                            update_source_status(
                                cfg.metadata_dir,
                                canon,
                                module,
                                va,
                                force=True,
                                clear_blockers=canon in MATCHED_STATUSES,
                                updated_by="lint",
                            )
                        else:
                            update_field(
                                cfg.metadata_dir,
                                va,
                                toml_key,
                                write_value,
                                module=module,
                                updated_by="lint",
                            )

                # Strip inline comment from source (file-only — the metadata
                # write above already owns the field; routing STATUS through
                # remove_annotation_key would raise, and removing any other
                # metadata key would delete the field we just migrated).
                # Already present in the store: the inline copy is still
                # stripped, so say so under --dry-run.  Either way this is a
                # strip, not a migration.  Count only lines actually removed.
                if dry_run:
                    if present:
                        console.print(
                            f"  [dim]Would strip[/dim] {untrusted_ident(r.filepath.name)} "
                            f"// {untrusted_ident(key)}: (already in metadata)"
                        )
                        inline_strip_count += 1
                    else:
                        fix_count += 1
                elif remove_inline_annotation_key(r.filepath, va, key):
                    if present:
                        inline_strip_count += 1
                    else:
                        fix_count += 1

        w029_fn_count = 0
        if fn_redundant:
            if dry_run:
                for fn_hit in fn_redundant:
                    console.print(
                        f"  [dim]Would drop[/dim] redundant cflags "
                        f"{untrusted_ident(fn_hit.module)} 0x{fn_hit.va:x} "
                        f"(inherited {fn_hit.inherited!r})"
                    )
                w029_fn_count = len(fn_redundant)
            else:
                w029_fn_count = remove_fields_batch(
                    cfg.metadata_dir,
                    [
                        {"module": fn_hit.module, "va": fn_hit.va, "keys": ["cflags"]}
                        for fn_hit in fn_redundant
                    ],
                )
        w029_preset_count = 0
        if preset_redundant:
            if dry_run:
                for preset_hit in preset_redundant:
                    console.print(
                        f"  [dim]Would drop[/dim] redundant preset "
                        f"cflags_presets.{untrusted_ident(preset_hit.module)}"
                    )
            w029_preset_count = drop_redundant_presets(cfg, preset_redundant, dry_run=dry_run)
            if dry_run and w029_preset_count == 0:
                w029_preset_count = len(preset_redundant)

        section_count = 0
        if section_hits:
            if dry_run:
                for section_hit in section_hits:
                    console.print(
                        f"  [dim]Would set[/dim] section {section_hit.section!r} "
                        f"for {untrusted_ident(section_hit.module)} "
                        f"0x{section_hit.va:x} (rebrew-data.toml)"
                    )
                section_count = len(section_hits)
            else:
                # One rebrew-data.toml rewrite for all hits, not one per symbol.
                section_updates: dict[tuple[str, int], dict[str, Any]] = {}
                for section_hit in section_hits:
                    hit_key = (section_hit.module, section_hit.va)
                    if hit_key in section_updates:
                        continue
                    existing = get_data_entry(cfg.metadata_dir, section_hit.va, section_hit.module)
                    if "section" in {k.lower() for k in existing}:
                        continue
                    section_updates[hit_key] = {
                        "module": section_hit.module,
                        "va": section_hit.va,
                        "fields": {"section": section_hit.section},
                        "updated_by": "lint",
                    }
                set_data_fields_batch(cfg.metadata_dir, list(section_updates.values()))
                section_count = len(section_updates)

        if not json_output:
            parts: list[str] = []
            # Merge the two strip streams: W010 unknown keys and redundant /
            # already-migrated inline copies are all pure source-line removals.
            all_stripped = strip_count + inline_strip_count
            if dry_run:
                if fix_count:
                    parts.append(f"{fix_count} inline annotations would be migrated")
                if all_stripped:
                    parts.append(f"{all_stripped} redundant inline lines would be stripped")
                if w029_fn_count:
                    parts.append(f"{w029_fn_count} redundant per-function cflags would be dropped")
                if w029_preset_count:
                    parts.append(f"{w029_preset_count} redundant cflags presets would be dropped")
                if section_count:
                    parts.append(f"{section_count} missing SECTIONs would be backfilled")
                if parts:
                    console.print(f"\n[yellow]Dry run:[/yellow] {'; '.join(parts)}")
            else:
                if fix_count:
                    parts.append(
                        f"migrated {fix_count} inline annotations to rebrew-functions.toml"
                    )
                if all_stripped:
                    parts.append(f"stripped {all_stripped} redundant inline lines")
                if w029_fn_count:
                    parts.append(f"dropped {w029_fn_count} redundant per-function cflags")
                if w029_preset_count:
                    parts.append(f"dropped {w029_preset_count} redundant cflags presets")
                if section_count:
                    parts.append(f"backfilled {section_count} missing SECTIONs")
                if parts:
                    console.print(f"\n[green]Fixed:[/green] {'; '.join(parts)}")

    if error_count > 0:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


if __name__ == "__main__":
    main_entry()
