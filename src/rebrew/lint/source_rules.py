"""C source, body, style, comment-stripping, assembly, and per-file lint rules."""

import logging
import re
import threading
from pathlib import Path
lazy import bisect
lazy from collections.abc import Callable, Iterable
lazy from typing import Any

from rebrew.lint.metadata_rules import (
    METADATA_TO_FOUND,
    UNCLAIMED_STATUSES,
    LintResult,
    MissingSection,
    block_defines,
    check_config_rules,
    check_E001_kind,
    check_E002_va,
    check_E004_status_value,
    check_E008_size_value,
    check_E013_duplicate_va,
    check_E015_kind_consistency,
    check_E017_contradictory,
    check_format_errors,
    check_W005_blocker,
    check_W006_source,
    check_W015_va_case,
    check_W016_section,
    check_W018_cflags,
    check_W037_data_definition,
)
lazy from rebrew.c_syntax.parser import (
    find_extern_variables,
    find_function_name_in_node,
    function_definition_spans,
    mask_msvc_syntax,
    msvc_asm_spans,
    parse_c_source,
)
lazy from rebrew.config import DEFAULT_LINT_MAX_LINE_LENGTH, ProjectConfig, inventory_path_for
lazy from rebrew.metadata.anchors import metadata_comments, parse_address_anchors
lazy from rebrew.metadata.bindings import (
    DATA_KINDS,
    MIN_VALID_VA,
    SourceBinding,
    file_backed_by_metadata,
    function_rows_for_file,
    min_valid_va_for,
)
lazy from rebrew.metadata.data import load_data_metadata
lazy from rebrew.metadata.functions import canonical_status, load_metadata
lazy from rebrew.metadata.source_provenance import (
    function_definition_hashes,
    load_source_provenance,
)
lazy from rebrew.utils import (
    last_change_ns,
    preset_module_key,
    read_source_text,
    rel_display_path,
    resolved_path,
)
lazy from rebrew.workspace.names import is_placeholder_name
lazy from rebrew.workspace.status import MATCHED_STATUSES

__all__ = [
    "DATA_SECTION_NAMES",
    "build_function_index",
    "check_E023_naked_asm",
    "check_W020_asm_dump",
    "check_W021_duplicate_globals",
    "check_W022_zero_init_bss",
    "check_W023_default_func_names",
    "check_W028_stale_annotation",
    "check_W030_va_order",
    "check_body_rules",
    "check_style_rules",
    "data_section_names_for",
    "documented_assembly_symbols",
    "function_containing_va",
    "lazy_metadata_entries",
    "lint_file",
    "retired_leftover",
    "source_headers",
    "staleness_fix",
    "strip_all",
    "strip_c_comments_strings",
]

log = logging.getLogger(__name__)

# Event scanning for strip_c_comments_strings: the characters that can change
# state, per state.  Ordinary runs between events are copied as bulk slices;
# the per-character loop this replaced was ~70% of batch-lint CPU.
_STRIP_CODE_RE = re.compile(r"""["'/]""")
_STRIP_BLOCK_RE = re.compile(r"\*/")
_STRIP_STR_RE = re.compile(r"""[\\"]""")
_STRIP_CHR_RE = re.compile(r"""[\\']""")
_STRIP_CODE, _STRIP_BLOCK, _STRIP_STR, _STRIP_CHR = range(4)

_SNAKE_CASE_RE = re.compile(r"[a-z_][a-z0-9_]*")
_CAMEL_CASE_RE = re.compile(r"[a-z][a-zA-Z0-9]*")

#: W022 exemption set per loaded data-metadata document, and the document
#: itself pinned so a freed entry's ``id`` is never reused as a live key.
DATA_SECTION_NAMES: dict[int, frozenset[str]] = {}
_DATA_SECTION_NAMES_OWNER: dict[int, dict[tuple[str, int], dict[str, Any]]] = {}
_DATA_SECTION_NAMES_MAX = 4
# The owner hit, the two eviction clears, and the two stores are one
# check-then-act over two parallel dicts — the same discipline as
# ``annotation._metadata_file_index``.  Held only for the dict work; the name
# set is built outside it.
_DATA_SECTION_NAMES_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Function index and VA staleness / ordering checks
# ---------------------------------------------------------------------------


def function_containing_va(
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


def build_function_index(
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
        # there (min_valid_va_for returns 0); dropping it fired a false W028 on
        # a legitimate function at VA 0.
        if va < min_valid_va_for(cfg):
            continue
        starts.add(va)
        spans.append((va, va + max(int(f.get("size", 0) or 0), 1), str(f.get("name", ""))))
    spans.sort()
    return starts, spans


def staleness_fix(cfg: ProjectConfig | None) -> str:
    """Pick a staleness fix hint from which artifact is newer.

    Stale annotations have two very different causes: the target binary was
    replaced (refresh the function inventory), or the annotations moved / the inventory
    no longer reflects the target (re-annotate) — recommending ``rebrew
    intake`` for the second case is wrong.  The binary's last change time
    against the list's mtime is a cheap proxy: a binary newer than the list
    means it plausibly changed after the list was written; a list at least as
    new as the binary means the binary cannot have changed since, so the
    bindings (or a list regenerated from a different binary, e.g. a rebuild)
    are at fault.  Falls back to a cause-neutral message when either file's
    timestamp is unavailable.
    """
    binary_newer: bool | None = None
    try:
        bin_path = Path(str(getattr(cfg, "target_binary", "")))
        rev_dir = getattr(cfg, "reversed_dir", None)
        inv_path = inventory_path_for(rev_dir, cfg) if rev_dir else None
        if inv_path is not None and bin_path.is_file() and inv_path.is_file():
            # Nanosecond timestamps: second-granularity mtimes tie when a
            # rebuild and inventory refresh land in the same wall-clock second
            # (common on scripts / coarse Docker volume clocks), and the
            # binary's change time catches a rebuild that restored its mtime.
            binary_newer = last_change_ns(bin_path.stat()) > inv_path.stat().st_mtime_ns
    except OSError:
        binary_newer = None

    annotate = "re-annotate the moved functions (`rebrew skeleton <new_va>` or edit the bound VA)"
    if binary_newer is True:
        return (
            "The target binary is newer than the function inventory — it likely changed: "
            "re-run `rebrew intake` / `rebrew binary functions` to refresh it, then " + annotate
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
        "changed, re-run `rebrew intake` / `rebrew binary functions` to refresh it; "
        "otherwise " + annotate + " (or regenerate the inventory if it was built from a "
        "different binary, e.g. a rebuilt artifact)"
    )


def check_W028_stale_annotation(
    result: LintResult,
    va_int: int,
    module: str,
    cfg: ProjectConfig | None,
    function_index: tuple[set[int], list[tuple[int, int, str]]] | None,
    status: str = "",
    metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> None:
    """Warn when a FUNCTION/STUB kind VA matches no function start (W028).

    A stale FUNCTION/STUB metadata binding has a VA that
    no longer corresponds to a function in the current binary.  After a
    binary update or a re-discovery the function either moved — the binding
    now points *inside* another function's span — or was removed (no
    function at that VA).  Either way ``rebrew test``/``verify`` compile
    against the wrong bytes and status/todo keep reporting phantom
    functions.

    Uses the target's discovery inventory (the same file ``rebrew intake`` /
    ``discover`` write) as ground truth.  ``LIBRARY`` bindings are excluded
    (import stubs) and ``GLOBAL``/``DATA`` bindings are data, not code;
    bindings of a different target module are filtered by the caller's
    config.  Silent when no function index is available.
    """
    if function_index is None:
        return
    target_module_name = getattr(cfg, "module", None) if cfg is not None else None
    if target_module_name and module and module != target_module_name:
        return  # another target's module — E012 already flags the module
    starts, spans = function_index
    if va_int in starts:
        return
    # A byte-matched annotation outranks the inventory.  The inventory comes
    # from heuristic discovery (rizin + a capstone sweep), which merges
    # adjacent functions when the boundary is only `ret` + alignment padding;
    # EXACT/RELOC means this VA already compiled and compared byte-for-byte
    # against the target there, which is strictly stronger evidence than a
    # sweep's guess.  Warning on those is a false positive that cannot be
    # actioned -- "re-annotate the bound VA" would break a matched function.
    # guild-rebrew hit 15 of these at once, including an EXACT row whose
    # supposed host was split from it by `ret; nop; nop` at 0x1000d92d.
    if status.upper() in MATCHED_STATUSES:
        return
    host = function_containing_va(spans, va_int)
    # The same merge, shown by the annotations themselves: the host's start is
    # an annotated function whose SIZE ends at or before this binding, so the
    # two annotations tile the host's range and discovery joined them.
    if host is not None and metadata is not None:
        try:
            host_size = int(metadata.get((module, host[0]), {}).get("size") or 0)
        except TypeError, ValueError:
            host_size = 0
        if host_size and host[0] + host_size <= va_int:
            return
    # Append the staleness fix hint only to the first stale address in the
    # file — repeating it per binding would drown the signal.
    hint = staleness_fix(cfg) if not any(c == "W028" for _, c, _ in result.warnings) else ""
    if host is not None:
        result.warning(
            result.binding_line,
            "W028",
            f"annotation VA 0x{va_int:x} points inside function "
            f"'{host[2] or 'a function'}' (moved/merged) — re-annotate the "
            "bound VA or refresh the function inventory (`rebrew binary functions`)" + hint,
        )
    else:
        result.warning(
            result.binding_line,
            "W028",
            f"annotation VA 0x{va_int:x} has no function in the current "
            "function inventory (removed or shifted) — re-annotate the bound VA "
            "or refresh the function inventory (`rebrew binary functions`)" + hint,
        )


def check_W030_va_order(result: LintResult, all_headers: list[Any], lines: list[str]) -> None:
    """Warn when a module's FUNCTION/STUB definitions do not ascend by VA (W030).

    The linker lays out a translation unit's functions in source order, so a
    definition placed above a lower-VA one links at the wrong address and
    displaces every function between them.  Bindings with only comments or
    blank lines between them share one body (identical copies at several VAs)
    and count as one definition, placed by its lowest VA.  Each module is
    checked on its own: a binding for another build carries that build's VA.
    """
    groups: list[dict[str, tuple[int, int]]] = []
    prev_line = -1
    prev_definition = 0
    for found_keys, _flags in all_headers:
        if found_keys.get("KIND", "") not in ("FUNCTION", "STUB"):
            continue
        try:
            va = int(found_keys.get("VA", ""), 16)
        except ValueError:
            continue
        line = int(found_keys.get("_LINE", "1"))
        definition = int(found_keys.get("_DEFINITION_LINE", "0"))
        if not definition:
            continue
        between = lines[prev_line : line - 1] if prev_line >= 0 else ["code"]
        separate = (
            definition != prev_definition
            if definition and prev_definition
            else any(t.strip() and not t.lstrip().startswith("//") for t in between)
        )
        if not groups or separate:
            groups.append({})
        mod = found_keys.get("MODULE", "")
        cur = groups[-1].get(mod)
        groups[-1][mod] = (va, line) if cur is None else (min(va, cur[0]), cur[1])
        prev_line = line
        prev_definition = definition
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


# ---------------------------------------------------------------------------
# Assembly provenance, naked/asm-dump, globals, comments, and style checks
# ---------------------------------------------------------------------------


def documented_assembly_symbols(
    source: str,
    filepath: Path,
    target_modules: Iterable[str] | None,
    metadata_dir: Path,
) -> set[str]:
    """Symbols in *filepath* whose original assembly is documented and current.

    A ``source document-assembly`` record only exempts assembly while the
    recorded definition hash still matches the file, so editing the body
    invalidates the exemption.

    Evidence is looked up for every module that claims a row in this file, not
    only the module of the target being linted.  A unified source tree holds
    files annotated for one target while `rebrew lint --all-targets` lints the
    others, and the evidence belongs to the file, not to the lint target.
    """
    folded = {preset_module_key(str(module)) for module in (target_modules or set()) if module}
    if not folded:
        return set()
    try:
        relative = resolved_path(filepath).relative_to(resolved_path(metadata_dir)).as_posix()
        records = [
            record
            for record in load_source_provenance(metadata_dir)
            if record.file == relative and record.module in folded
        ]
        hashes = function_definition_hashes(source) if records else {}
        return {r.symbol for r in records if hashes.get(r.symbol) == r.source_hash}
    except OSError, ValueError, ImportError:
        # The batch artifact check reports unusable records; they never exempt assembly.
        return set()


def lazy_metadata_entries(cfg: Any, filepath: Path) -> dict[tuple[str, int], dict[str, Any]] | None:
    """Function rows for one file's metadata directory, or None when unavailable."""
    try:
        from rebrew.metadata.functions import load_metadata as _load_metadata
        from rebrew.metadata.functions import resolve_metadata_dir

        directory = resolve_metadata_dir(cfg.metadata_dir if cfg else filepath.parent)
        return _load_metadata(directory, deepcopy=False)
    except OSError, ValueError:
        return None


def retired_leftover(
    filepath: Path,
    entries: dict[tuple[str, int], dict[str, Any]],
    metadata_dir: Path,
    project_root: Path,
) -> bool:
    """True when every anchor was retired from a different file, by name.

    The path-keyed INACTIVE check cannot follow a source file that was moved,
    so a reorganised tree would report each retired leftover as an unbound
    definition. Matching the retired claim's definition name keeps the check
    to reviewed history instead of guessing from content.
    """
    from rebrew.metadata.anchors import parse_address_anchors as _parse_anchors
    from rebrew.metadata.binding_history import retired_source_elsewhere

    try:
        source, _encoding = read_source_text(filepath)
    except OSError:
        return False
    from rebrew.c_syntax.parser import find_c_function_definitions
    from rebrew.config import address_comments_for_file

    anchors = _parse_anchors(
        source, syntax=address_comments_for_file(filepath, project_root=project_root)
    )
    if anchors:
        for anchor in anchors:
            entry = entries.get((preset_module_key(anchor.module), anchor.va))
            if entry is None:
                return False
            if not retired_source_elsewhere(
                entry, anchor.name, filepath, metadata_dir, project_root
            ):
                return False
        return True
    # An anchor-free leftover is recognised by the definitions it still holds:
    # each name must be one a reviewed change retired from a different file.
    definitions = [name for name, _line in find_c_function_definitions(source)]
    if not definitions:
        # A comment-only leftover (a retired switch arm) has nothing to bind;
        # recognise it by the name of the claim that used to live here.
        from rebrew.metadata.binding_history import validate_binding_history

        for entry in entries.values():
            for event in validate_binding_history(entry.get("binding_history", [])):
                previous = event.get("previous") or {}
                previous_file = str(previous.get("file") or "")
                if previous_file and Path(previous_file).name == filepath.name:
                    return True
        return False
    for name in definitions:
        retired = False
        for entry in entries.values():
            if retired_source_elsewhere(entry, name, filepath, metadata_dir, project_root):
                retired = True
                break
        if not retired:
            return False
    return True


def check_E023_naked_asm(
    result: LintResult,
    lines: list[str],
    code_lines: list[str],
    claimed_statuses: set[str] | None = None,
    documented: set[str] | None = None,
    *,
    strip_line: Callable[[str, bool], tuple[str, bool]] | None = None,
) -> None:
    """Flag whole-function ``__declspec(naked)`` + ``__asm`` dumps (E023).

    *code_lines* is the shared ``strip_all`` view of *lines*; the raw
    *lines* are still read by the padding checks below, which inspect
    literal source text.  A definition whose original assembly is documented
    with ``rebrew source document-assembly`` is exempt: whole-function asm is
    then evidenced reconstruction, not a decompilation shortcut.

    ``__declspec(naked)`` is only allowed for *minor padding* (1-2 alignment
    ``nop``/``int3`` bytes, e.g. ``_emit 0x90`` / ``_emit 0xCC`` or
    ``__asm nop``).  A whole-function naked body pasted from disassembly is
    not a decompilation and must be flagged as an error.

    Heuristic: a naked function whose asm body exceeds minor padding — more
    than 2 ``__asm``/``_emit`` lines, or any ``_emit`` byte that is not
    padding (``0x90``/``0xCC``) / non-nop mnemonic — is a whole-function
    dump and earns E023.  1-2 nops for alignment are tolerated silently.
    """
    if documented:
        source = "\n".join(lines)
        raw_source = bytearray(source.encode("utf-8", errors="surrogateescape"))
        for name, start, end in function_definition_spans(source):
            if name in documented:
                raw_source[start:end] = bytes(
                    10 if byte == 10 else 32 for byte in raw_source[start:end]
                )
        code_lines = strip_all(
            raw_source.decode("utf-8", errors="surrogateescape").split("\n"),
            strip_line=strip_line,
        )

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
    source = "\n".join(code_lines)
    raw = source.encode("utf-8", errors="surrogateescape")
    spans = msvc_asm_spans(source)
    assembly = [raw[start:end].decode("utf-8", errors="surrogateescape") for start, end in spans]
    if not assembly:
        assembly = [code for code in code_lines if "_emit" in code]
    payloads: list[list[str]] = []
    for block in assembly:
        for line in block.splitlines():
            # C comments/strings are already stripped; ';' starts an asm comment.
            payload = line.lower().split(";", 1)[0]
            payload = payload.replace("__asm", " ").replace("_asm", " ")
            words = payload.replace("{", " ").replace("}", " ").split()
            if words and words[0].endswith(":"):
                words = words[1:]
            if words:
                payloads.append(words)
    if not payloads:
        return

    padding_count = 0
    padding_only = True
    for words in payloads:
        i = 0
        while i < len(words):
            if words[i] == "nop":
                i += 1
            elif words[i : i + 2] in (
                ["int", "3"],
                ["_emit", "0x90"],
                ["_emit", "0xcc"],
                ["__emit", "0x90"],
                ["__emit", "0xcc"],
            ):
                i += 2
            else:
                padding_only = False
                break
            padding_count += 1
        if not padding_only:
            break
    if padding_only and padding_count <= 2:
        return

    claimed = sorted((claimed_statuses or set()) - UNCLAIMED_STATUSES)
    suffix = f" but STATUS claims {', '.join(claimed)}" if claimed else ""
    result.error(
        naked_line,
        "E023",
        f"whole-function __declspec(naked) + __asm/__emit is not allowed{suffix} — "
        "naked asm is only for minor padding (1-2 alignment bytes: nop / _emit 0x90 / 0xCC); "
        "decompile the function to C instead",
    )


def check_W020_asm_dump(
    result: LintResult,
    code_lines: list[str],
    source: str,
    rows: list[tuple[str, int, dict[str, Any]]],
    headers: list[tuple[dict[str, str], dict[str, bool]]],
    target_module_name: str | None,
    filepath: Path,
    metadata_dir: Path,
) -> None:
    """Warn once per undocumented assembly function, using its own target rows.

    A byte match alone does not establish original assembly provenance.
    Documented partial assembly can match bytes; its blocker suppresses only
    that definition. Naked assembly is handled by E023.
    """
    if not any("__asm" in code or "_emit" in code for code in code_lines):
        return
    from rebrew.source.rename_ops import c_name_from_symbol

    selected_rows = [
        row
        for module, _, row in rows
        if not target_module_name
        or preset_module_key(module) == preset_module_key(target_module_name)
    ]
    function_headers = [
        keys for keys, _ in headers if keys.get("KIND") in {"FUNCTION", "LIBRARY", "STUB"}
    ]
    if (
        target_module_name
        and (rows or function_headers)
        and not selected_rows
        and not any(
            preset_module_key(keys.get("MODULE", "")) == preset_module_key(target_module_name)
            for keys in function_headers
        )
    ):
        return
    definitions: list[tuple[int, int, str]] = []
    parsed = b""
    try:
        tree, parsed = parse_c_source(mask_msvc_syntax(source))
    except ImportError:
        tree = None
    pending = [tree.root_node] if tree is not None else []
    while pending:
        node = pending.pop()
        if node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            name = find_function_name_in_node(declarator, parsed) if declarator else None
            definitions.append((node.start_point[0] + 1, node.end_point[0] + 1, name or ""))
        else:
            pending.extend(reversed(node.children))
    definitions.sort()
    documented: set[str] = set()
    if target_module_name:
        try:
            relative = resolved_path(filepath).relative_to(resolved_path(metadata_dir)).as_posix()
            records = [
                record
                for record in load_source_provenance(metadata_dir)
                if record.file == relative
                and record.module == preset_module_key(target_module_name)
            ]
            hashes = function_definition_hashes(source) if records else {}
            documented = {r.symbol for r in records if hashes.get(r.symbol) == r.source_hash}
        except OSError, ValueError, ImportError:
            # The batch artifact check reports unusable records; they never exempt assembly.
            pass
    seen: set[int] = set()
    for i, code in enumerate(code_lines, start=1):
        if "_emit" not in code and "__asm" not in code:
            continue
        start, end, name = next(
            (definition for definition in definitions if definition[0] <= i <= definition[1]),
            (0, len(code_lines), ""),
        )
        if start in seen:
            continue
        seen.add(start)
        if start and any("__declspec(naked)" in line for line in code_lines[start - 1 : end]):
            continue
        definition_rows = [
            row
            for _, _, row in rows
            if name and name in (row.get("name"), c_name_from_symbol(str(row.get("symbol") or "")))
        ]
        own_rows = [row for row in definition_rows if row in selected_rows]
        previous_end = max((hi for _, hi, _ in definitions if hi < start), default=0)
        definition_headers = [
            keys
            for keys, _ in headers
            if start
            and previous_end < int(keys.get("_LINE", "0")) <= start
            and keys.get("KIND") in {"FUNCTION", "LIBRARY", "STUB"}
        ]
        own_headers = [
            keys
            for keys in definition_headers
            if not target_module_name
            or preset_module_key(keys.get("MODULE", "")) == preset_module_key(target_module_name)
        ]
        if (
            target_module_name
            and (definition_rows or definition_headers)
            and not (own_rows or own_headers)
        ):
            continue
        if any(row.get("blocker") for row in own_rows) or any(
            keys.get("BLOCKER") for keys in own_headers
        ):
            continue
        if name in documented:
            continue
        statuses = {canonical_status(str(row.get("status") or "")) for row in own_rows}
        statuses.update(canonical_status(keys.get("STATUS", "")) for keys in own_headers)
        claimed = sorted(statuses - UNCLAIMED_STATUSES - {""})
        kind = "_emit byte dump" if "_emit" in code else "inline __asm block"
        suffix = f"; STATUS claims {', '.join(claimed)}" if claimed else ""
        result.warning(
            i,
            "W020",
            f"{kind} in {name or '<unparsed definition>'}{suffix} — rewrite as C where possible "
            "or document original assembly provenance with a BLOCKER or "
            "rebrew source document-assembly",
        )


def check_W021_duplicate_globals(
    result: LintResult,
    lines: list[str],
    filepath: Path,
    seen_globals: dict[str, tuple[str, int, bool]] | None,
    bindings: list[SourceBinding],
    text: str,
) -> None:
    """Warn when a global's annotated address or initialized ownership conflicts.

    Catches the np-rebrew pattern where ``globals.c`` and another source both
    annotate/define the same global (g_ vs DAT_ collisions, duplicate
    definitions). ``seen_globals`` maps ``module:name`` to its defining path,
    address and initialized-definition flag, threaded across the batch like
    ``seen_vas``. Extern declarations at the owner's address are references,
    matching E013's progressive-ownership rule.

    The key carries the binding's module: a shared tree annotates the same
    symbol once per target (SERVER ``g_log_newline`` at 0x100270e4, the
    client's at 0x677ac8), and those are two binaries' globals, not a
    collision. Conflicting addresses or two initialized definitions under the
    same module still warn, including a DATA binding beside a GLOBAL binding.
    """
    if seen_globals is None or not any(binding.kind in DATA_KINDS for binding in bindings):
        return
    variables = {v.name: v for v in find_extern_variables(text, include_definitions=True)}
    for binding in bindings:
        if binding.kind not in DATA_KINDS or binding.name not in variables:
            continue
        variable = variables[binding.name]
        key = f"{binding.module}:{variable.name}"
        defines = block_defines(lines, variable.line - 1)
        previous = seen_globals.get(key)
        if (
            previous is not None
            and previous[0] != str(filepath)
            and (previous[1] != binding.va or (previous[2] and defines))
        ):
            result.warning(
                variable.line, "W021", f"global '{variable.name}' is also defined in {previous[0]}"
            )
        elif previous is None or defines:
            seen_globals[key] = (str(filepath), binding.va, defines)


def strip_c_comments_strings(line: str, in_block_comment: bool) -> tuple[str, bool]:
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


def strip_all(
    lines: list[str],
    *,
    strip_line: Callable[[str, bool], tuple[str, bool]] | None = None,
) -> list[str]:
    """Return the comment/string-stripped *code view* of every line.

    One stateful pass over the whole file.  E023, W020 and W022 read this
    shared view instead of each re-stripping every line themselves —
    previously four full strip passes per file on the batch-lint hot path.
    """
    fn = strip_line or strip_c_comments_strings
    out: list[str] = []
    in_block = False
    for line in lines:
        code, in_block = fn(line, in_block)
        out.append(code)
    return out


def _is_zero_initializer_node(val_node: Any, raw: bytes) -> bool:
    """True when an init_declarator value AST node is ``0`` or ``{ 0 }``."""
    text = raw[val_node.start_byte : val_node.end_byte].decode("utf-8", errors="surrogateescape")
    compact = "".join(text.split())
    return compact in ("0", "{0}")


def check_W022_zero_init_bss(
    result: LintResult, code_lines: list[str], data_section_names: frozenset[str] = frozenset()
) -> None:
    """Flag file-scope zero initializers (W022) via tree-sitter-c."""
    from rebrew.c_syntax.parser import find_declarator_identifier
    from rebrew.c_syntax.parser import mask_msvc_syntax as _mask
    from rebrew.c_syntax.parser import parse_c_source as _parse

    source = "\n".join(code_lines)
    if "= 0" not in source and "={0}" not in source and "= {" not in source and "=0" not in source:
        return
    tree, raw = _parse(_mask(source))
    for child in tree.root_node.named_children:
        if child.type != "declaration":
            continue
        for sub in child.named_children:
            if sub.type != "init_declarator":
                continue
            val = sub.child_by_field_name("value")
            if val is None or not _is_zero_initializer_node(val, raw):
                continue
            decl = sub.child_by_field_name("declarator")
            name = find_declarator_identifier(decl, raw) if decl is not None else ""
            if data_section_names and name in data_section_names:
                continue
            result.warning(
                int(child.start_point.row) + 1,
                "W022",
                "file-scope zero initializer (= {0} / = 0) puts the global in "
                ".data, not .bss — leave it uninitialized to keep the PE small",
            )


def check_W023_default_func_names(result: LintResult, lines: list[str], pedantic: bool) -> None:
    """Warn about functions with default names (W023) when --pedantic is used."""
    if not pedantic:
        return
    from rebrew.c_syntax.parser import find_c_function_definitions

    for func_name, line_num in find_c_function_definitions("\n".join(lines)):
        if is_placeholder_name(func_name):
            result.warning(
                line_num,
                "W023",
                f"Function '{func_name}' has a default name; consider renaming to something meaningful",
            )


def check_style_rules(result: LintResult, cfg: ProjectConfig | None) -> None:
    """Check code style rules from project config (W024-W027)."""
    if cfg is None:
        return
    lines = result._lines

    # Naming convention (W024): function definitions should follow the rule.
    naming = getattr(cfg, "lint_naming_convention", "none")
    if naming != "none":
        from rebrew.c_syntax.parser import find_c_function_definitions

        for func_name, line_num in find_c_function_definitions("\n".join(lines)):
            if naming == "snake_case" and not _SNAKE_CASE_RE.fullmatch(func_name):
                result.warning(line_num, "W024", f"Function '{func_name}' should be snake_case")
            elif naming == "camelCase" and not _CAMEL_CASE_RE.fullmatch(func_name):
                result.warning(line_num, "W024", f"Function '{func_name}' should be camelCase")

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


def check_body_rules(result: LintResult, lines: list[str], has_new: bool) -> None:
    """Check code presence (W003); struct size comments are not required."""
    has_code = any(
        line.strip() and not line.strip().startswith(("//", "/*", "*")) for line in lines
    )
    if not has_code and has_new:
        result.warning(1, "W003", "File has no function implementation")


def data_section_names_for(entries: dict[tuple[str, int], dict[str, Any]]) -> frozenset[str]:
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
            cached = DATA_SECTION_NAMES.get(key)
            if cached is not None:
                return cached
    names = frozenset(
        name
        for entry in entries.values()
        if entry.get("section") in (".data", ".bss")
        for name in (
            str(entry.get("name") or ""),
            # A C data definition links as ``_name``; the source spells ``name``.
            str(entry.get("link_symbol") or "").removeprefix("_"),
        )
        if name
    )
    with _DATA_SECTION_NAMES_LOCK:
        if len(DATA_SECTION_NAMES) >= _DATA_SECTION_NAMES_MAX:
            DATA_SECTION_NAMES.clear()
            _DATA_SECTION_NAMES_OWNER.clear()
        DATA_SECTION_NAMES[key] = names
        _DATA_SECTION_NAMES_OWNER[key] = entries
    return names


def source_headers(lines: list[str]) -> list[tuple[dict[str, str], dict[str, bool]]]:
    """Structural address headers only; never parse state from comments."""
    return [
        (
            {"KIND": a.kind, "MODULE": a.module, "VA": f"0x{a.va:08x}", "_LINE": str(a.line)},
            {"has_new": True},
        )
        for a in parse_address_anchors("\n".join(lines))
    ]


def lint_file(
    filepath: Path,
    cfg: ProjectConfig | None = None,
    *,
    seen_vas: dict[Any, str] | None = None,
    seen_va_defines: dict[Any, bool] | None = None,
    seen_globals: dict[str, tuple[str, int, bool]] | None = None,
    preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
    preloaded_data_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
    preloaded_historical_sources: set[Path] | None = None,
    preloaded_source_files: frozenset[str] | None = None,
    metadata_directory: Path | None = None,
    function_index: tuple[set[int], list[tuple[int, int, str]]] | None = None,
    pedantic: bool = False,
    section_for_va: Any = None,
    section_hits: list[MissingSection] | None = None,
    strip_line: Callable[[str, bool], tuple[str, bool]] | None = None,
    retired_leftover_fn: Callable[[Path, dict[tuple[str, int], dict[str, Any]], Path, Path], bool]
    | None = None,
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
        seen_globals: Optional dict mapping module/global name to path, address
                      and initialized ownership for W021. Will be mutated.
        preloaded_metadata: Pre-loaded metadata dict (avoids per-file I/O in batch).
        preloaded_data_metadata: Pre-loaded data metadata dict (avoids per-file I/O in batch).
        preloaded_historical_sources: Resolved retired paths shared by a batch.
        preloaded_source_files: Metadata-root-relative names that hold a
                        source-purpose row, shared by a batch. Without this,
                        every linted file re-reads and stat-walks the store.
        metadata_directory: Metadata location already resolved by the batch.
        function_index: ``(starts, spans)`` from the target function list
                        (built once per batch); enables the W028
                        annotation-staleness cross-check.
        section_for_va: Optional callable mapping a VA to its binary section
                        name; enables W016 autofix collection in
                        ``section_hits``.
        section_hits: Optional list collecting :class:`MissingSection` for
                      DATA/GLOBAL bindings whose VA resolves to a section.
        pedantic: Enable the pedantic-only W023 (default function name) check.
        strip_line: Optional line-stripping callback (used by test hooks).
        retired_leftover_fn: Optional retired-leftover callback (used by test hooks).

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
    result._lines = lines

    from rebrew.config import address_comments_for_file

    syntax = address_comments_for_file(filepath, project_root=getattr(cfg, "root", None))
    for line, key in metadata_comments(text, syntax=syntax):
        result.error(
            line, "E024", f"{key} belongs in metadata; source accepts ADDRESS anchors only"
        )
    from rebrew.metadata.source_provenance import load_source_files

    directory = metadata_directory or (cfg.metadata_dir if cfg else filepath.parent)
    relative = rel_display_path(resolved_path(filepath), resolved_path(directory))
    if preloaded_source_files is not None:
        supported = relative in preloaded_source_files
    else:
        supported = any(record.file == relative for record in load_source_files(directory))
    if supported:
        result._kind_counts["SUPPORT"] += 1
        check_body_rules(result, lines, True)
        return result
    is_retired_leftover = retired_leftover_fn or retired_leftover
    try:
        from rebrew.metadata.bindings import source_bindings, strict_bindings

        # Lint reports a record its source disagrees with; reads skip it.
        with strict_bindings():
            bindings = source_bindings(
                text,
                filepath,
                None,
                None,
                directory,
                project_root=getattr(cfg, "root", None),
            )
        definition_lines: dict[str, int] = {}
        if any(a.is_function for a in bindings):
            from rebrew.c_syntax.parser import find_c_function_definitions

            definition_lines = dict(find_c_function_definitions(text))
        all_headers = [
            (
                {
                    "KIND": a.kind,
                    "MODULE": a.module,
                    "VA": f"0x{a.va:08x}",
                    "_LINE": str(a.line or definition_lines.get(a.name, 1)),
                    "_DEFINITION_LINE": str(definition_lines.get(a.name, 0)),
                },
                {"has_new": True},
            )
            for a in bindings
        ]
        all_headers.sort(key=lambda header: int(header[0]["_LINE"]))
    except ValueError as exc:
        # A leftover of a move can still carry an anchor whose VA now belongs to
        # another claim; that is history, not a conflicting new definition.
        entries = lazy_metadata_entries(cfg, filepath)
        if entries is not None:
            from rebrew.metadata.functions import resolve_metadata_dir
            from rebrew.workspace.config import walk_up_to_root

            directory = resolve_metadata_dir(directory)
            project_root = cfg.root if cfg else walk_up_to_root(directory) or directory
            if is_retired_leftover(filepath, entries, directory, project_root):
                result._kind_counts["INACTIVE"] += 1
                return result
        result.error(1, "E001", str(exc))
        return result

    # Load per-directory metadata (keys: (module, va_int) -> {toml_field: value}).
    # Accept pre-loaded dicts from callers that process many files in the same directory
    # (avoids repeated I/O for the common batch-lint case).
    # metadata_dir walks the tree upward per access, so resolve it only when a
    # preload does not already answer for this directory.
    _metadata_dir = (
        None
        if preloaded_metadata is not None and preloaded_data_metadata is not None
        else directory
    )
    _metadata_entries = (
        preloaded_metadata
        if preloaded_metadata is not None
        else load_metadata(_metadata_dir, deepcopy=False)
    )
    _data_metadata_entries = (
        preloaded_data_metadata
        if preloaded_data_metadata is not None
        else load_data_metadata(_metadata_dir, deepcopy=False)
    )
    if not all_headers:
        from rebrew.metadata.binding_history import historical_source_files
        from rebrew.metadata.functions import resolve_metadata_dir
        from rebrew.workspace.config import walk_up_to_root

        directory = resolve_metadata_dir(directory)
        project_root = cfg.root if cfg else walk_up_to_root(directory) or directory
        resolved = resolved_path(filepath) if _metadata_entries else None
        if (
            resolved in preloaded_historical_sources
            if preloaded_historical_sources is not None
            else any(
                resolved in historical_source_files(row, directory, project_root)
                for row in _metadata_entries.values()
                if row.get("binding_history", []) != []
            )
        ):
            # Explicitly retired TUs remain reviewable source, outside compilation.
            result._kind_counts["INACTIVE"] += 1
            return result
        if is_retired_leftover(filepath, _metadata_entries, directory, project_root):
            # A file whose every anchor names a definition another file's claim
            # retired is the leftover of a move, not a new unbound TU.
            result._kind_counts["INACTIVE"] += 1
            return result
    # A pure-C file whose row names this path is annotated. A anchor-free
    # file with no row is still E001.
    metadata_backed = False
    if not all_headers:
        metadata_backed = file_backed_by_metadata(
            filepath,
            directory,
            project_root=getattr(cfg, "root", None),
            function_entries=_metadata_entries,
            data_entries=_data_metadata_entries,
        )
        if not metadata_backed:
            all_headers = [({}, {"has_new": False})]
    result._headers = all_headers

    # Module keys this project recognises, folded once per file: the NFC +
    # upper of every binding in cfg.target_modules is per-annotation work below
    # otherwise, on a tree with thousands of annotated blocks.
    _own_module = getattr(cfg, "module", None) if cfg is not None else None
    _target_modules = getattr(cfg, "target_modules", None) or (
        {_own_module} if _own_module else set()
    )
    _known_folded = {preset_module_key(str(item)) for item in _target_modules if item}

    # Statuses claimed by this file's annotations (for E023 diagnostics).
    _file_statuses: set[str] = set()
    # Modules with a row or annotation in this file: assembly evidence is looked
    # up for all of them, because one unified file can belong to several targets.
    _file_modules: set[str] = set()

    if metadata_backed:
        # A pure-C file carries no metadata bindings: its blockers and statuses are
        # the store rows that name it, for this target only.
        for _row_module, _row_va, _row in function_rows_for_file(
            filepath,
            directory,
            _metadata_entries,
            project_root=getattr(cfg, "root", None),
        ):
            if _row_module:
                _file_modules.add(str(_row_module))
            if _own_module and preset_module_key(_row_module) != preset_module_key(_own_module):
                continue
            _row_status = canonical_status(str(_row.get("status") or ""))
            if _row_status:
                _file_statuses.add(_row_status)

    for found_keys, flags in all_headers:
        result.binding_line = int(found_keys.get("_LINE", "1"))

        mod = found_keys.get("MODULE", "")
        if mod:
            _file_modules.add(mod)
        va_str = found_keys.get("VA", "")

        # Populate metadata fields for this source binding.
        _metadata_sourced_keys: set[str] = set()
        _va_int: int | None = None
        _metadata_size: str | None = None
        _metadata_override: dict[str, Any] = {}
        if mod and va_str:
            try:
                _va_int = int(va_str, 16)
                _metadata_override = _metadata_entries.get((mod, _va_int), {})
                _metadata_size = str(_metadata_override.get("size", "")).strip() or None
                for _toml_key, _found_key in METADATA_TO_FOUND.items():
                    if _toml_key not in _metadata_override:
                        continue
                    store_val = str(_metadata_override[_toml_key])
                    found_keys[_found_key] = store_val
                    _metadata_sourced_keys.add(_found_key)
            except (ValueError, KeyError) as exc:
                # A malformed metadata key drops the field from the drift
                # comparison, so a disagreeing SIZE would go unreported.
                log.debug("unreadable metadata at %s: %s", result.binding_line, exc)

        ctx = f"[{mod} {va_str}] " if mod and va_str else ""

        if len(all_headers) > 1:
            result.context_prefix = ctx
        else:
            result.context_prefix = ""

        if not check_format_errors(result, flags):
            continue

        if flags["has_new"]:
            kind = found_keys.get("KIND", "")
            check_E001_kind(result, kind)

            va_int = check_E002_va(
                result, va_str, min_va=min_valid_va_for(cfg) if cfg else MIN_VALID_VA
            )

            # EVERY block of a multi-function file, keyed on (module, va) so
            # a multi-module file whose blocks share a VA is not flagged.
            # DATA/GLOBAL also pass the binding kind + body so the check can
            # tell a second definition (real collision) from an extern/bare
            # claim beside the single definition (progressive ownership).
            check_E013_duplicate_va(
                result,
                va_int,
                va_str,
                filepath,
                seen_vas,
                module=mod,
                kind=kind,
                lines=lines,
                binding_line=result.binding_line,
                seen_va_defines=seen_va_defines,
            )

            if kind in ("FUNCTION", "STUB") and va_int is not None:
                check_W028_stale_annotation(
                    result,
                    va_int,
                    mod,
                    cfg,
                    function_index,
                    # The status is the store's (overlaid above), so an
                    # EXACT/RELOC row suppresses W028 for a stale annotation.
                    status=canonical_status(str(found_keys.get("STATUS", ""))),
                    metadata=_metadata_entries,
                )

            if kind not in DATA_KINDS:
                # A stacked shared-source block for ANOTHER target answers to
                # its own target's defaults, not this one's — flagging it for
                # missing CFLAGS here is misattribution (ADR-010).
                _own_key = preset_module_key(_own_module) if _own_module else ""
                _mod_key = preset_module_key(mod) if mod else ""
                if not (
                    cfg is not None
                    and _own_module
                    and mod
                    and _mod_key != _own_key
                    and _mod_key in _known_folded
                ):
                    check_W018_cflags(result, found_keys, cfg)
            # For DATA/GLOBAL: overlay data metadata fields (size, section, note).
            # SIZE follows the same store-wins rule as SECTION and NOTE.
            elif va_int is not None and mod:
                _ds_override = _data_metadata_entries.get((mod, va_int), {})
                # A data symbol's SIZE lives in rebrew-data.toml, so read it
                # from that store rather than the function store.  A DATA/GLOBAL
                # block resolved from the function store would report a size it
                # never read.
                if "size" in _ds_override:
                    _metadata_size = str(_ds_override["size"]).strip() or None
                _DS_TO_FOUND = {"size": "SIZE", "section": "SECTION", "note": "NOTE"}
                for _ds_key, _ds_found_key in _DS_TO_FOUND.items():
                    if _ds_key not in _ds_override:
                        continue
                    store_val = str(_ds_override[_ds_key])
                    found_keys[_ds_found_key] = store_val
                    _metadata_sourced_keys.add(_ds_found_key)

            module = found_keys.get("MODULE", "")
            # Canonicalize so a hand-edited `status = "exact"` feeds
            # E015/E017/MATCHED_STATUSES the same way update_source_status does.
            status = canonical_status(found_keys.get("STATUS", ""))

            # Collect summary data during the lint pass (used by _print_summary).
            if kind:
                result._kind_counts[kind] += 1
            if status:
                result._status_counts[status] += 1
                _file_statuses.add(status)

            check_E015_kind_consistency(result, kind, module, status, cfg)
            check_W005_blocker(result, status, found_keys)
            check_W006_source(result, module, found_keys, cfg)
            check_E017_contradictory(result, status, kind)
            check_E004_status_value(result, status)
            check_E008_size_value(result, _metadata_size)
            check_config_rules(result, found_keys, cfg)

            check_W015_va_case(result, va_str)
            check_W016_section(
                result,
                kind,
                found_keys,
                module=mod,
                va_int=_va_int,
                section_for_va=section_for_va,
                section_hits=section_hits,
            )

    result.context_prefix = ""
    # Names of globals annotated section=".data" in rebrew-data.toml — W022
    # exemption (the original binary stored the zero-init data in .data).
    _data_section_names = data_section_names_for(_data_metadata_entries)
    code_lines = strip_all(lines, strip_line=strip_line)  # one strip pass shared by E023/W020/W022
    if not _file_modules and _own_module:
        _file_modules.add(_own_module)
    _documented_assembly = documented_assembly_symbols(text, filepath, _file_modules, directory)
    check_E023_naked_asm(
        result,
        lines,
        code_lines,
        _file_statuses,
        _documented_assembly,
        strip_line=strip_line,
    )
    check_W020_asm_dump(
        result,
        code_lines,
        text,
        function_rows_for_file(
            filepath,
            directory,
            _metadata_entries,
            project_root=getattr(cfg, "root", None),
        ),
        all_headers,
        _own_module,
        filepath,
        directory,
    )
    check_W021_duplicate_globals(result, lines, filepath, seen_globals, bindings, text)
    check_W022_zero_init_bss(result, code_lines, _data_section_names)
    if cfg is not None:
        check_W037_data_definition(result, text, filepath, cfg, directory)
    check_body_rules(
        result,
        lines,
        metadata_backed or (all_headers[0][1]["has_new"] if all_headers else False),
    )
    check_W023_default_func_names(result, lines, pedantic)
    check_W030_va_order(result, all_headers, lines)
    check_style_rules(result, cfg)
    return result
