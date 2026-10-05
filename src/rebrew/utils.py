"""utils.py — the leaf helpers every other rebrew module can depend on.

This module has no rebrew binary imports list, so anything here may be called from
anywhere without a cycle.  That freedom is also its cost: the name says
nothing about what it owns, so the map below is the index.  Helpers are
grouped by concern and stay in that group; a new helper joins the group
it belongs to rather than starting a sixth.

- **Text and identifiers**: ``strip_bidi_format``, ``strip_body``,
  ``strip_comment_blocks``, ``strip_generated_timestamp``, ``filename_component``,
  ``is_safe_c_ident``, ``c_comment_safe``, ``pe_name_token``, ``fold_ident``,
  ``ascii_slug``, ``preset_module_key``, ``toml_safe``,
  ``parse_int_literal``, ``parse_c_integer_literal``, ``source_newline``,
  ``safe_shlex_split``, ``untrusted_literal`` / ``untrusted_text`` /
  ``untrusted_ident``
- **Source and config reading**: ``read_source_text`` / ``read_compile_source``
  (with the LRU memo and its ``clear_source_text_memo`` reset),
  ``resolved_path`` (a stat-keyed ``Path.resolve`` memo),
  ``split_source_lines`` / ``join_source_lines``,
  ``detect_source_encoding``, ``read_toml_text``, ``load_tomllib``,
  ``load_toml_for_write`` / ``load_toml_for_write_strict``, ``read_json_text``
- **Atomic and locked writes**: ``atomic_write_text`` / ``atomic_write_bytes``,
  ``atomic_write_locked``, ``file_lock`` / ``file_handle_lock``,
  ``preserve_corrupt``, ``source_backup`` / ``SOURCE_BACKUP_DIRNAME`` (the
  pre-run copy of a source a sweep rewrites in place)
- **Subprocesses**: ``run_process_group`` (process-tree teardown, timeout,
  captured pipes), ``interruptible_pool`` (leaving the pool does not wait on
  the queue), ``watch_files``
- **Host environment**: ``container_runtime`` / ``DEFAULT_CONTAINER_RUNTIME`` /
  ``CONTAINER_RUNTIMES``, ``find_install_tool``, ``md5_file``,
  ``SOURCE_CHECKOUT`` (the contributor checkout, ``None`` in an install),
  ``rel_display_path``
- **Presentation helpers**: ``console`` (the stderr sink every module imports,
  so target strings are scrubbed once and for all), ``BYTES_PER_MIB``,
  ``clip_span``,
  ``merged_span_bytes``, ``floor_pct``, ``close_response``,
  ``retry_backoff_delay``, ``retry_log_detail``
  (plus ``RETRYABLE_HTTP_STATUS``, ``RETRY_LOG_MESSAGE_CHARS``)

``utils`` is not a place for domain logic.  A helper that knows about a
toolchain, a metadata field, or a rebrew-project layout belongs in the
module that owns that concept (``toolchain``, ``metadata``, ``workspace``,
``config``), not here.  The metadata TOML key algebra, document parse/build
and write lock moved out to :mod:`rebrew.metadata_doc`; the scratch-directory
placement policy moved out to :mod:`rebrew.temp_dirs`; ``preset_module_key``
stays here because it is identifier text normalization that outlives any one
store.
"""

import bisect
import codecs
import concurrent.futures
import contextlib
import hashlib
import logging
import math
import os

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]
import re
import shlex
import signal
import subprocess
import threading
import time
import tomllib
import unicodedata
from collections import OrderedDict
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import IO, Any, override

import tomlkit
from rich.console import Console
from rich.errors import MarkupError
from rich.markup import escape as rich_escape
from tomlkit import TOMLDocument
from tomlkit.exceptions import InternalParserError, ParseError

logger = logging.getLogger(__name__)

# The rebrew package's own vendored toolchains (toolchain/msvc/5.0-win32, toolchain/watcom/2.0-win32,
# ...).  Projects resolve compiler paths project-relative first, then fall
# back here so a freshly-inited project works without a local tools/ symlink.
#: A C89 identifier: ASCII only.  ``str.isidentifier()`` follows Python's
#: Unicode rules and accepts ``café`` or ``名前``, which MSVC6-era compilers
#: reject.  Names from linker output, BinSync, or the CLI are external text.
_C_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")

#: A PE import/export name as a single linker token.  Import-descriptor and
#: name-table strings are raw bytes from the target binary, decoded latin-1 and
#: cut only at a NUL, so a newline or quote in a crafted import survives into
#: the generated scaffolding.  Generated C reaches a compiler, so anything
#: outside the token set becomes ``_`` rather than being emitted verbatim.
#: Space is inside the set: a C++ import name may carry one, and a space
#: cannot end a line or leave a quoted directive.
_PE_NAME_RE = re.compile(r"[^A-Za-z0-9_.@?$ ]+")
_PE_NAME_MAX_CHARS = 255

#: Path components are one filesystem entry: no separators, no drive letters,
#: no leading dot or dash.  200 chars leaves room under the usual 255-byte
#: NAME_MAX once a suffix such as ``.best.c`` is appended.
_FILENAME_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._@-]+")
_FILENAME_COMPONENT_MAX_CHARS = 200
#: DOS device names Windows reserves in *every* case and with *any* suffix:
#: ``NUL``, ``NUL.json`` and ``nul.best.c`` all address the null device, so a
#: write silently succeeds and the bytes are discarded.  Matched against the
#: part before the first dot, which is what Win32's name parser reads.
_RESERVED_WINDOWS_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"{prefix}{n}" for prefix in ("COM", "LPT") for n in range(1, 10)}
)
#: Mode :func:`atomic_write_text` creates its temp file with, and therefore
#: installs at the target path.  Owner read/write only for a non-secret file
#: rebrew owns; a writer holding a credential passes something tighter.
_DEFAULT_FILE_MODE = 0o644

#: Invisible reordering / hiding characters: the bidi embeddings, overrides and
#: isolates, the left-to-right and right-to-left marks, the zero-width
#: space/joiners, the word joiner, the soft hyphen, and the BOM.  They occupy
#: no glyph, so ``sub_A\u202etxt`` renders as ``sub_txt_A`` and a status column
#: beside a hostile symbol name can be made to read as something else.  Symbol
#: names reach a display surface from a target binary, BinSync state, or an
#: import table, so every surface that prints one drops them.
_BIDI_FORMAT_CHARS = frozenset(
    "\u00ad"  # soft hyphen
    "\u180e"  # mongolian vowel separator
    "\u200b\u200c\u200d"  # zero-width space / non-joiner / joiner
    "\u200e\u200f"  # left-to-right / right-to-left mark
    "\u202a\u202b\u202c\u202d\u202e"  # embeddings, overrides, pop
    "\u2060\u2061\u2062\u2063\u2064"  # word joiner, invisible operators
    "\u2066\u2067\u2068\u2069"  # isolates
    "\ufeff"  # zero-width no-break space (BOM)
)
_BIDI_FORMAT_TABLE = {ord(char): None for char in _BIDI_FORMAT_CHARS}
#: Every stripped character is non-ASCII, so a regex scan over ordinary text
#: finds nothing and skips the per-character translate table.  Dashboard
#: responses scrub every cell of every row, where the translate dominated.
_BIDI_FORMAT_SEARCH = re.compile(f"[{''.join(sorted(_BIDI_FORMAT_CHARS))}]")


def strip_bidi_format(value: str) -> str:
    """*value* with the invisible reordering and hiding characters removed."""
    if _BIDI_FORMAT_SEARCH.search(value) is None:
        return value
    return value.translate(_BIDI_FORMAT_TABLE)


#: C0/C1 controls except tab and newline, rendered as ``\xNN``.  Error text
#: carries remote response bodies and binary-derived names; a raw ESC would
#: let them drive the terminal (OSC title/clipboard writes, screen clears).
_TERMINAL_CONTROL_CHARS = {
    code: f"\\x{code:02x}"
    for code in (*range(0x20), *range(0x7F, 0xA0))
    if code not in (ord("\t"), ord("\n"))
}


def untrusted_literal(value: object) -> str:
    """*value* as terminal-safe text with its own characters left alone.

    Same stripping as :func:`untrusted_text` (no invisible bidi or zero-width
    formatting characters, C0/C1 controls other than tab/newline shown as
    ``\\xNN``) but without Rich markup escaping, for a block printed with
    ``markup=False``: an LLM prompt preview or a C snippet, where ``a[i]`` and
    ``[bold]`` are the text under review and escaping them would misreport it.
    """
    return strip_bidi_format(str(value)).translate(_TERMINAL_CONTROL_CHARS)


#: Line separators and tab, rendered as ``\xNN`` on top of
#: :data:`_TERMINAL_CONTROL_CHARS`.  An identifier is one line, so a name
#: carrying a newline would otherwise print a second line of its own into a
#: verdict block, where it reads as another result row.
_LINE_BREAK_CHARS = {
    ord("\n"): r"\x0a",
    ord("\r"): r"\x0d",
    ord("\t"): r"\x09",
}


def untrusted_ident(value: object) -> str:
    """*value* as one line of literal terminal text.

    :func:`untrusted_text` for a symbol, module, section, file, or status
    printed in a table cell or a one-line verdict: markup is escaped, invisible
    and control characters are rendered as ``\\xNN``, and so is a line break,
    because a name carrying one prints a fabricated extra line into the block
    an analyst reads verdicts out of.
    """
    return rich_escape(untrusted_literal(value).translate(_LINE_BREAK_CHARS))


def untrusted_text(value: object) -> str:
    """*value* as literal terminal text.

    Rich markup is escaped, invisible bidi and zero-width formatting characters
    are dropped, and C0/C1 controls other than tab/newline are rendered as
    ``\\xNN``.  Use for any string derived from a target binary, a project file,
    or a remote service: ``[bold]`` in an import name would otherwise restyle
    the table, a raw ESC would drive the terminal (OSC title/clipboard writes,
    screen clears), and a right-to-left override would reorder a neighbouring
    column to read as a different name or status.
    """
    return rich_escape(untrusted_literal(value))


class _TargetSafeConsole(Console):
    """Console a hostile target string cannot crash or hijack.

    Rich parses every ``[tag]`` in what it prints as markup, and rebrew prints
    symbol, module, section, and import names read straight out of the target
    binary. Two consequences a call site can forget to handle:

    - a name carrying ``[/bold]`` or ``[/]`` makes Rich raise
      :class:`~rich.errors.MarkupError` out of ``print``. No layer above
      catches it, so one crafted symbol ended any command that printed it
      with a traceback;
    - a name carrying ESC (OSC 52 clipboard writes, screen clears) or a
      right-to-left override reached the terminal verbatim and reordered the
      column beside it.

    :func:`untrusted_text` is the per-call fix and keeps the intended markup
    styled. This is the backstop for the calls that do not use it: strings are
    scrubbed of control and invisible characters (no rebrew-authored output
    contains one, so styled output is unchanged), and a markup parse failure
    is re-emitted as literal text instead of propagating.
    """

    @override
    def print(self, *objects: Any, **kwargs: Any) -> None:  # (rich API)
        scrubbed = tuple(untrusted_literal(obj) if isinstance(obj, str) else obj for obj in objects)
        try:
            super().print(*scrubbed, **kwargs)
        except MarkupError:
            # The offending markup is a hostile (or malformed) tag inside the
            # data, not rebrew's own styling. Re-emit without markup: the tags
            # show as the literal text they are, and a table cell's row
            # survives instead of taking the whole command down.
            kwargs.pop("markup", None)
            kwargs.pop("highlight", None)
            super().print(*scrubbed, markup=False, highlight=False, **kwargs)


#: Every module's user-facing stderr output goes through this one console, so
#: the guard covers the whole CLI rather than the commands that remembered
#: :func:`untrusted_text`.  Import it instead of constructing a bare
#: ``Console(stderr=True)``.
console = _TargetSafeConsole(stderr=True)


#: Bytes per mebibyte.  Every byte figure rebrew sizes, caps, or displays is
#: binary (1024-based), so the unit is MiB, not the decimal MB.  A project's
#: ``[cache] size_limit_mib`` and every size cap and MiB readout convert
#: through this one constant.
BYTES_PER_MIB = 1024 * 1024


def clip_span(starts: list[int], va: int, size: int) -> int:
    """*size* cut so ``va + size`` does not pass the next of the sorted *starts*.

    A discoverer that misses a function start reports the previous entry
    running through it; summing such sizes counts the neighbour twice.
    """
    i = bisect.bisect_right(starts, va)
    return min(size, starts[i] - va) if i < len(starts) else size


def merged_span_bytes(ranges: list[tuple[int, int]], section: tuple[int, int] | None = None) -> int:
    """Total bytes of the union of the ``(start, end)`` *ranges*.

    Overlapping and empty ranges count once, so two names for one address do
    not inflate a coverage figure.  With *section* ``(va, size)`` the union is
    clipped to it, which keeps a size that runs past the section from reporting
    coverage above 100%.
    """
    if section is not None:
        section_va, section_size = section
        limit = section_va + section_size
        ranges = [
            (max(start, section_va), min(end, limit))
            for start, end in ranges
            if min(end, limit) > max(start, section_va)
        ]
    spans = sorted((start, end) for start, end in ranges if end > start)
    if not spans:
        return 0
    total = 0
    current_start, current_end = spans[0]
    for start, end in spans[1:]:
        if start <= current_end:
            current_end = max(current_end, end)
        else:
            total += current_end - current_start
            current_start, current_end = start, end
    return total + (current_end - current_start)


def floor_pct(part: float, whole: float, decimals: int = 1) -> float:
    """``100 * part / whole`` rounded down to *decimals* places; 0.0 when *whole* is 0.

    Progress and match figures must not round up: to nearest, 2809 of 2810
    matched reads "100.0%" with one function still unmatched.
    """
    if not whole:
        return 0.0
    scale = float(10**decimals)
    # The inner round absorbs float error (57.3 * 10 = 572.99...).
    return math.floor(round(100.0 * part / whole * scale, 6)) / scale


def is_safe_c_ident(name: str) -> bool:
    """True when *name* can be emitted verbatim as a C identifier."""
    return bool(_C_IDENT_RE.match(name))


def c_comment_safe(text: str) -> str:
    """Make *text* safe to embed inside a generated ``/* ... */`` comment.

    Every string a generated source carries from the analyzed binary is
    attacker-controlled: Ghidra symbol names, PE section names, annotation
    notes.  A ``*/`` in any of them closes the enclosing comment early and
    puts the rest of the line into the header body as C, which ``rebrew test``
    then compiles.  Splitting ``*/`` keeps the text readable while defusing
    the breakout; other non-printable characters become spaces.
    """
    return "".join(" " if not ch.isprintable() else ch for ch in text.replace("*/", "* /"))


def pe_name_token(name: str | None) -> str:
    """Render a PE import/export name as a single linker-safe token.

    A PE name is attacker-controlled whenever the target binary is: it comes
    from the import descriptor or the hint/name table, so a crafted binary
    can carry a newline, quote, or brace.  Those reach generated C, which
    ``rebrew build layout`` compiles and links, so a newline would end the
    enclosing comment and compile its remainder as top-level C.  Substituting
    every byte outside the token set keeps the import present (the IAT slot
    ordering the scaffolding exists to force is preserved) while making the
    rest inert.  A name that is entirely out-of-set collapses to ``_``.
    """
    if not name:
        return ""
    # No strip: a leading underscore is ordinary in MSVC import names, and
    # the substitution already guarantees a non-empty result.
    return _PE_NAME_RE.sub("_", name)[:_PE_NAME_MAX_CHARS]


_CHECKOUT = Path(__file__).resolve().parents[2]
#: The rebrew source checkout (editable install), or None for a wheel install,
#: where ``parents[2]`` is the interpreter's ``lib/python3.X`` and must be
#: neither searched for vendored tools nor written to.
SOURCE_CHECKOUT: Path | None = _CHECKOUT if (_CHECKOUT / "pyproject.toml").is_file() else None

# Process-lifetime source text memo keyed by (resolved path, mtime_ns, size, inode).
# verify/test/catalog re-read the same tree multiple times per run; a bounded
# LRU collapses those duplicate syscalls without pinning unbounded content.
# Guarded: verify -j N reads the same sources from worker threads.
_SOURCE_TEXT_MEMO: OrderedDict[tuple[str, int, int, int], tuple[str, str]] = OrderedDict()
# A game tree is thousands of sources, and verify/status re-read each one.
# 512 evicted the head of a 4000-file scan before the scan finished, so the
# second pass re-read every file (78 ms vs 31 ms). 8192 small bodies is the
# ceiling; raise it when a scan larger than that shows up in a profile.
_SOURCE_TEXT_MEMO_MAX = 8192
_SOURCE_TEXT_MEMO_LOCK = threading.Lock()
# resolved path -> its live memo keys, so a write invalidates in O(1)
# instead of scanning the whole LRU.
_SOURCE_TEXT_MEMO_BY_PATH: dict[str, set[tuple[str, int, int, int]]] = {}

# ``str(path)`` -> its resolved path, for :func:`read_source_text`.  The body
# memo is keyed by the resolved path, but producing it walks every component
# with an ``lstat``; a whole-tree scan reads each source more than once
# (``naming.load_data`` then ``lint.count_migratable_files``), so that walk
# ran once per read.  Bounded and lock-guarded with the body memo it fronts.
_RESOLVED_SOURCE_PATHS: OrderedDict[str, Path] = OrderedDict()
_RESOLVED_SOURCE_PATHS_MAX = _SOURCE_TEXT_MEMO_MAX


def _resolved_source_path(filepath: Path) -> Path:
    """Return *filepath* resolved, memoized per input path spelling."""
    key = str(filepath) if filepath.is_absolute() else f"{Path.cwd()}\0{filepath}"
    with _SOURCE_TEXT_MEMO_LOCK:
        hit = _RESOLVED_SOURCE_PATHS.get(key)
        if hit is not None:
            _RESOLVED_SOURCE_PATHS.move_to_end(key)
            return hit
    resolved = filepath.resolve()
    with _SOURCE_TEXT_MEMO_LOCK:
        _RESOLVED_SOURCE_PATHS[key] = resolved
        _RESOLVED_SOURCE_PATHS.move_to_end(key)
        while len(_RESOLVED_SOURCE_PATHS) > _RESOLVED_SOURCE_PATHS_MAX:
            _RESOLVED_SOURCE_PATHS.popitem(last=False)
    return resolved


# ``(spelling, mtime_ns, size, ino)`` -> resolved path.  The stat is from
# ``lstat``, so a content edit or a symlink retarget misses and resolves
# again.  Unlike :func:`_resolved_source_path`, this key notices a changed
# final component, which is what header and source identity need.
_RESOLVED_PATHS: OrderedDict[tuple[str, int, int, int], Path] = OrderedDict()
_RESOLVED_PATHS_MAX = 2048
_RESOLVED_PATHS_LOCK = threading.Lock()


def resolved_path(path: Path) -> Path:
    """Return *path* resolved, memoized on its spelling and ``lstat`` identity.

    The key is ``(spelling, mtime_ns, size, ino)``.  A relative spelling
    includes the current directory.  ``OSError`` from ``lstat`` falls through
    to ``Path.resolve()`` and is not memoized.  The memo stores the resolved
    path, not file bytes: callers that need to notice a content edit still
    ``stat`` the result.
    """
    try:
        st = path.lstat()
    except OSError:
        return path.resolve()
    spelling = str(path) if path.is_absolute() else f"{Path.cwd()}\0{path}"
    key = (spelling, st.st_mtime_ns, st.st_size, st.st_ino)
    with _RESOLVED_PATHS_LOCK:
        hit = _RESOLVED_PATHS.get(key)
        if hit is not None:
            _RESOLVED_PATHS.move_to_end(key)
            return hit
    resolved = path.resolve()
    with _RESOLVED_PATHS_LOCK:
        _RESOLVED_PATHS[key] = resolved
        _RESOLVED_PATHS.move_to_end(key)
        while len(_RESOLVED_PATHS) > _RESOLVED_PATHS_MAX:
            _RESOLVED_PATHS.popitem(last=False)
    return resolved


def _memo_forget(memo_key: tuple[str, int, int, int]) -> None:
    """Unlink *memo_key*'s path from the index, dropping an emptied entry."""
    keys = _SOURCE_TEXT_MEMO_BY_PATH.get(memo_key[0])
    if keys is not None:
        keys.discard(memo_key)
        if not keys:
            del _SOURCE_TEXT_MEMO_BY_PATH[memo_key[0]]


def _memo_drop(memo_key: tuple[str, int, int, int]) -> None:
    """Remove one entry from the source text memo and its path index."""
    _SOURCE_TEXT_MEMO.pop(memo_key, None)
    _memo_forget(memo_key)


def _memo_store(memo_key: tuple[str, int, int, int], value: tuple[str, str]) -> None:
    """Insert an entry, evicting the LRU tail until there is room."""
    if memo_key in _SOURCE_TEXT_MEMO:
        _SOURCE_TEXT_MEMO.move_to_end(memo_key)
        return
    while len(_SOURCE_TEXT_MEMO) >= _SOURCE_TEXT_MEMO_MAX:
        oldest, _value = _SOURCE_TEXT_MEMO.popitem(last=False)
        _memo_forget(oldest)
    _SOURCE_TEXT_MEMO[memo_key] = value
    _SOURCE_TEXT_MEMO_BY_PATH.setdefault(memo_key[0], set()).add(memo_key)


#: Comment opener of the stamp line both generated headers carry.
_GENERATED_STAMP_PREFIX = "* Generated:"


_CONTAINER_RUNTIME_RE = re.compile(r"^[a-zA-Z0-9_\-\./]+$")
DEFAULT_CONTAINER_RUNTIME = "docker"
#: Bare runtime names rebrew knows how to drive.  Anything else is a typo
#: (``dockre``, ``Podmam``) that would otherwise surface as a spawn failure
#: from deep inside a compile; a value carrying a path separator is passed
#: through as a path to a runtime binary instead of being name-checked.
CONTAINER_RUNTIMES = ("docker", "podman", "nerdctl")


def container_runtime(runtime: str | None = None) -> str:
    """The container runtime used for docker-shipped tools.

    Configurable via ``REBREW_CONTAINER_RUNTIME`` so podman (crun-backed,
    daemonless) or nerdctl can be used instead of dockerd — same knob the Go
    port honors.  Defaults to ``docker``.  Empty / whitespace-only values
    are treated as unset (``os.environ.get`` alone would return ``""`` and
    break every ``docker``/``podman`` invocation).  A bare name outside
    :data:`CONTAINER_RUNTIMES` raises here rather than at exec time.

    Pass *runtime* to validate a candidate value without reading (or writing)
    the process environment; ``rebrew.config.env_knob_errors`` uses that to
    report a mistyped variable through ``rebrew cfg effective``.

    Raises :class:`rebrew.config.ConfigError`, which is also a ``ValueError``:
    the compile call sites do not guard this call, so a bare ``ValueError``
    escaped as a traceback from the middle of a build instead of the CLI's
    error message.
    """
    from rebrew.config import ConfigError

    if runtime is None:
        runtime = os.environ.get("REBREW_CONTAINER_RUNTIME", DEFAULT_CONTAINER_RUNTIME)
    runtime = runtime.strip() or DEFAULT_CONTAINER_RUNTIME
    if not _CONTAINER_RUNTIME_RE.fullmatch(runtime):
        raise ConfigError(f"REBREW_CONTAINER_RUNTIME={runtime!r} contains invalid characters")
    if "/" not in runtime and runtime not in CONTAINER_RUNTIMES:
        raise ConfigError(
            f"REBREW_CONTAINER_RUNTIME={runtime!r} is not a known container runtime "
            f"({', '.join(CONTAINER_RUNTIMES)}); set a path to the binary to use another one"
        )
    return runtime


def find_install_tool(rel: str | Path) -> Path | None:
    """Resolve *rel* (a project-relative ``tools/...`` path) against the
    rebrew install's own vendored tree, or None when absent.

    Used by the config/compile layers so vendored toolchains (MSVC, Watcom,
    Delphi, diec) resolve out of the box; a project-local ``tools/`` symlink
    (via ``rebrew init --link-tools-from``) still takes precedence because
    callers check the project path first.
    """
    if SOURCE_CHECKOUT is None:
        return None
    p = SOURCE_CHECKOUT / rel
    return p if p.exists() else None


def md5_file(path: Path) -> str:
    """MD5 hex digest of a file, matching BinSync's ``binary_hash``.

    IDA (``retrieve_input_file_md5().hex()``), Ghidra (``executableMD5``),
    Binary Ninja (``md5(bv.file.raw)``), and declib's file loader all hash the
    raw binary bytes, so this reproduces the value a BinSync state dir stores.
    """
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, lambda: hashlib.md5(usedforsecurity=False)).hexdigest()


# Candidate encodings for C sources, most strict first.  MSVC6-era sources
# are often CP1252 (Western) or Shift-JIS (Japanese games) — the exact
# audience this tool targets.  UTF-8 first keeps the common case
# byte-identical; Shift-JIS second so Japanese sources round-trip (CP1252 is
# last because it decodes *every* byte sequence, so it must be the catch-all
# fallback rather than a first guess).
_SOURCE_ENCODINGS = ("utf-8", "shift_jis", "cp1252")

#: Half-width katakana, the single-byte Shift-JIS range 0xA1-0xDF.  The rest of
#: Shift-JIS's single-byte set (0x81-0x9F, 0xE0-0xFC) covers currency signs and
#: the ``\\ | ~ ¬`` block — the same bytes CP1252 spells as ``é è ê ë``.
_SHIFT_JIS_HALFWIDTH_KATAKANA = range(0xFF61, 0xFFA0)


def _looks_shift_jis(text: str) -> bool:
    """True when *text* holds Japanese, not just bytes Shift-JIS accepts.

    Every 0xE0-0xFC byte is a valid single-byte Shift-JIS character, so a
    CP1252 source holding ``café`` (0xE9) decodes as Shift-JIS without error
    and every accented letter reads as katakana.  The write-back is still
    byte-identical, so the misdecode is silent: only the text a caller prints,
    compares, or slices is wrong.  Requiring a CJK or kana character keeps a
    real Japanese source on Shift-JIS and hands the Latin one to CP1252, which
    round-trips the same bytes just as well.
    """
    return any(
        "぀" <= ch <= "ヿ"  # hiragana, katakana, CJK punctuation
        or "一" <= ch <= "鿿"  # CJK unified ideographs
        or "豈" <= ch <= "﫿"  # CJK compatibility ideographs
        or "＀" <= ch <= "￯"  # half-width and full-width forms
        or ch in "。、〜「」"  # kana punctuation
        or ord(ch) in _SHIFT_JIS_HALFWIDTH_KATAKANA
        for ch in text
    )


def detect_source_encoding(data: bytes) -> str:
    """Return the encoding *data* is in: UTF-8 when it decodes cleanly,
    otherwise Shift-JIS, else CP1252, else Latin-1.

    Reading a legacy-encoded source as UTF-8 with ``errors="replace"`` and
    writing it back permanently replaces every non-ASCII byte with U+FFFD;
    detecting the real encoding on read lets write-backs round-trip
    byte-for-byte.  Ordering note: cp1252 is tried last; shift_jis is
    stricter and catches Japanese sources first, but only once
    :func:`_looks_shift_jis` confirms the decoded text is actually Japanese.

    A UTF-8 BOM answers ``utf-8-sig`` rather than ``utf-8``: plain UTF-8
    keeps U+FEFF as the text's first character, which hides a leading
    ``// FUNCTION:`` marker from every line-anchored parser, while
    ``utf-8-sig`` strips it on read and re-emits it on write-back.
    """
    if data.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    for enc in _SOURCE_ENCODINGS:
        try:
            decoded = data.decode(enc)
        except UnicodeDecodeError:
            continue
        if enc == "shift_jis" and not _looks_shift_jis(decoded):
            continue
        return enc
    # Only a CP1252 undefined byte (0x81, 0x8D, 0x8F, 0x90, 0x9D) gets here.
    # Latin-1 maps every byte to one code point, so the write-back encodes to
    # the same bytes; a cp1252 decode would yield U+FFFD, which cp1252 cannot
    # encode (write-back raises UnicodeEncodeError).  0x80-0x9F then read as
    # C1 controls instead of CP1252 glyphs.
    return "latin-1"


def split_source_lines(text: str, *, keepends: bool = False) -> list[str]:
    """*text* split into lines on ``\\n`` only, terminators dropped.

    ``str.splitlines`` also breaks on VT, FF, NEL (U+0085), LS (U+2028) and
    PS (U+2029).  Those code points are legal inside a C string literal and a
    C comment — text pasted from a web page or a spreadsheet carries them —
    and :func:`read_source_text` hands back a UTF-8 source with them intact,
    so a write-back that joins the result with ``"\\n"`` turns each of them
    into a newline and corrupts the file.  Only ``\\n`` ends a line in C
    source.

    Trailing-newline handling matches ``splitlines``: a final ``"\\n"``
    produces no empty last element, so ``"\\n".join(split_source_lines(t))``
    plus that terminator reproduces a ``\\n``-only file byte for byte.

    *keepends* returns each line with its own ``"\\n"`` (a CRLF line keeps its
    ``"\\r"``) for an edit path that splices a line in and rejoins with
    ``"".join``, where the terminator has to survive the round trip.
    """
    if keepends:
        lines: list[str] = []
        start = 0
        while True:
            idx = text.find("\n", start)
            if idx == -1:
                if start < len(text):
                    lines.append(text[start:])
                return lines
            lines.append(text[start : idx + 1])
            start = idx + 1
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def join_source_lines(original: str, lines: list[str]) -> str:
    """*lines* joined with ``\\n``, keeping *original*'s trailing newline.

    The pair for :func:`split_source_lines`.  A writer that always appends
    ``"\\n"`` adds a terminator to a file that had none, which shows up as
    unrelated churn in every later diff.
    """
    text = "\n".join(lines)
    return text + "\n" if original.endswith("\n") else text


def binary_fingerprint(binary: str | Path) -> str:
    """``mtime_ns:size:ino`` for *binary*, or ``""`` when unreadable.

    The one cheap change detector the analysis caches key on: a recompile
    that rewrites the file changes mtime or inode even when the bytes are
    identical, and a copy of the same bytes gets its own inode.
    """
    try:
        st = Path(binary).stat()
    except OSError:
        return ""
    return f"{st.st_mtime_ns}:{st.st_size}:{st.st_ino}"


def read_compile_source(filepath: Path) -> str:
    """Read *filepath* for a compile/GA round-trip (lossless byte identity).

    Uses ``utf-8`` + ``surrogateescape`` so a cp1252/Shift-JIS source keeps
    every on-disk byte as a code point that
    ``Path.write_text(..., errors="surrogateescape")`` can write back
    unchanged.  :func:`read_source_text` is for annotation/edit paths that
    need a real Unicode decode (and must pass the detected encoding on
    write-back); feeding its output into a UTF-8-only compile staging
    rewrite turns ``Caf\\xe9`` into UTF-8 ``Caf\\xc3\\xa9`` and breaks
    byte-identical string literals under MSVC.
    """
    return filepath.read_text(encoding="utf-8", errors="surrogateescape")


def source_newline(text: str) -> str:
    """The line ending *text* uses, for text spliced into it.

    The first terminator decides, so a file whose head is LF and tail is CRLF
    (already mixed) is treated as the LF file it mostly is.  Written lines
    must use the result: a hardcoded ``"\\n"`` separator leaves a CRLF source
    with one LF-terminated line, and the next read/rewrite propagates the
    mixture through the whole file.
    """
    idx = text.find("\n")
    if idx > 0 and text[idx - 1] == "\r":
        return "\r\n"
    return "\n"


def read_source_text(filepath: Path) -> tuple[str, str]:
    """Read *filepath* tolerantly, returning ``(text, detected_encoding)``.

    Pass the returned encoding to :func:`atomic_write_text` when writing the
    file back so legacy-encoded sources are not corrupted by a UTF-8 write.
    A source with an undefined CP1252 byte (0x81/0x8D/0x8F/0x90/0x9D) that is
    not Shift-JIS either reads as Latin-1, so it still round-trips.

    Bounded path+mtime memo: verify/test/catalog often re-scan the same
    tree several times per run (prepare_entries, build_name_to_va,
    scan_globals).  A content-digest parse memo still re-reads every file;
    this layer skips the syscall+decode when the inode metadata is unchanged.
    """
    resolved = _resolved_source_path(filepath)
    try:
        st = resolved.stat()
    except OSError:
        # Fall through to a direct read so the caller's OSError path matches
        # the pre-cache behaviour (missing file, permission, etc.).
        data = filepath.read_bytes()
        encoding = detect_source_encoding(data)
        return data.decode(encoding, errors="replace"), encoding
    memo_key = (str(resolved), st.st_mtime_ns, st.st_size, st.st_ino)
    with _SOURCE_TEXT_MEMO_LOCK:
        hit = _SOURCE_TEXT_MEMO.get(memo_key)
        if hit is not None:
            # Refresh LRU order: move-to-end so hot sources stay.
            _SOURCE_TEXT_MEMO.move_to_end(memo_key)
            return hit
    data = resolved.read_bytes()
    encoding = detect_source_encoding(data)
    text = data.decode(encoding, errors="replace")
    with _SOURCE_TEXT_MEMO_LOCK:
        _memo_store(memo_key, (text, encoding))
    return text, encoding


def clear_source_text_memo() -> None:
    """Drop every cached source body, its path index, and the resolved-path memo."""
    with _SOURCE_TEXT_MEMO_LOCK:
        _SOURCE_TEXT_MEMO.clear()
        _SOURCE_TEXT_MEMO_BY_PATH.clear()
        _RESOLVED_SOURCE_PATHS.clear()


def read_toml_text(path: Path) -> str:
    """Read a TOML file as text, tolerating a leading UTF-8 BOM.

    Windows editors (Notepad, some IDEs) write ``EF BB BF``; decoding with
    plain ``utf-8`` leaves U+FEFF as the first character, and both
    ``tomllib`` and ``tomlkit`` then reject the file.  ``utf-8-sig`` strips
    the BOM so a BOM-prefixed ``rebrew-project.toml`` still loads.
    """
    return path.read_text(encoding="utf-8-sig")


#: Every surrogate code point, for the :func:`toml_safe` membership test.
_SURROGATE_CHARS = frozenset(chr(code) for code in range(0xD800, 0xE000))
#: What a surrogate becomes in stored text (see :func:`toml_safe`).
_REPLACEMENT_CHAR = "�"


def toml_safe(value: Any) -> Any:
    """Strip control characters from strings before TOML serialization.

    Walk tables and arrays too: locals/comments contain nested strings.
    Sanitization must not merge distinct table keys; a collision raises
    before the owning writer replaces the store.

    tomlkit>=0.15 emits some controls (e.g. ESC) as ``\\e``, which is
    not valid TOML and fails the next parse — a Ghidra comment or note
    carrying one would corrupt the whole metadata file, key or value.  This
    runs on both: :func:`rebrew.metadata_doc.build_metadata_doc` sends every
    qualified key through it too, because a target name carrying a control
    character writes a key no reader can parse back.  Tab/newline survive
    (valid TOML escapes); other C0/C1 controls are dropped.

    A surrogate is replaced with U+FFFD, not dropped.  A legacy cp1252 or
    Shift-JIS source read by :func:`read_compile_source` yields lone
    surrogates (U+DC80-U+DCFF) for bytes that are not valid UTF-8, and a
    symbol name, Ghidra comment, or note copied out of one carries them here.
    tomlkit writes such a code point through as itself rather than escaping it,
    so the value reaches ``atomic_write_locked`` unchanged and its ``utf-8``
    encode raises ``UnicodeEncodeError`` — the whole write aborts and the
    field is lost with it.  Dropping the character instead would make
    ``"Café"`` and ``"Cafe"`` the same stored note; U+FFFD keeps the
    position of the byte that was there.
    """
    if isinstance(value, dict):
        safe: dict[Any, Any] = {}
        for key, item in value.items():
            clean_key = toml_safe(key)
            if clean_key in safe:
                raise ValueError(f"TOML keys collide after sanitization: {key!r}")
            safe[clean_key] = toml_safe(item)
        return safe
    if isinstance(value, (list, tuple)):
        return [toml_safe(item) for item in value]
    if not isinstance(value, str):
        return value
    return "".join(
        _REPLACEMENT_CHAR if ch in _SURROGATE_CHARS else ch
        for ch in value
        if ord(ch) >= 0x20 or ch in ("\t", "\n")
    )


def load_tomllib(path: Path) -> dict[str, Any]:
    """Parse *path* with :mod:`tomllib`, tolerating a UTF-8 BOM.

    Prefer this over ``tomllib.load`` on a binary handle: CPython's tomllib
    does not strip a BOM from bytes either, so ``open(..., \"rb\")`` alone
    still fails on Notepad-saved configs.
    """
    return tomllib.loads(read_toml_text(path))


def read_json_text(path: Path) -> str:
    """Read a JSON file as text, tolerating a leading UTF-8 BOM.

    The JSON counterpart of :func:`read_toml_text`.  ``json.loads`` rejects a
    string whose first character is U+FEFF (``Unexpected UTF-8 BOM``), and
    several of the files read this way come from outside rebrew: a Ghidra
    export, ``compile_commands.json`` from an external build tool, a
    hand-kept residue baseline.  A Windows editor that adds ``EF BB BF`` to
    one of them turns a readable file into a parse error, which several
    callers report as "corrupt" and drop.
    """
    return path.read_text(encoding="utf-8-sig")


def _fsync_path(path: Path) -> None:
    """Best-effort ``fsync`` of an openable file or directory path.

    A filesystem that refuses the open or the sync (some container overlay
    mounts, Windows without ``O_RDONLY`` on a directory) must not fail an
    otherwise successful write.
    """
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


@contextlib.contextmanager
def _atomic_replace(filepath: Path) -> Iterator[Path]:
    """Yield a sibling temp path that is published onto *filepath* on a clean exit.

    On any failure the temp file is removed and the original exception is
    re-raised, so a crash or a full disk never leaves a partial write (or a
    stray ``.tmp`` sibling) at the target.  A read-only destination directory
    is reported with the target path instead of a bare errno 13.
    """
    tmp_path = filepath.with_name(
        f"{filepath.name}.{os.getpid()}.{threading.get_ident()}.{time.monotonic_ns()}.tmp"
    )
    try:
        yield tmp_path
        _fsync_path(tmp_path)
        try:
            os.replace(tmp_path, filepath)
        except PermissionError as exc:
            raise PermissionError(
                f"{exc}: cannot write next to {filepath} (directory is read-only?) — "
                "pass an explicit output path"
            ) from exc
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise
    _fsync_path(filepath.parent)


def strip_generated_timestamp(text: str) -> str:
    """*text* without its ``Generated:`` line.

    Header regenerators rewrite that line on every run; comparing the rest is
    what makes a rewrite idempotent and free of git churn.

    Only the header stamp matches, never any line that merely mentions the
    word: an annotation note is free text, and a bare substring test dropped
    the declaration carrying it from both sides of the comparison, so a
    changed note regenerated as "unchanged".

    Line endings are normalized so the comparison does not report a rewrite
    for a CRLF file whose freshly generated twin is LF, and only ``\n`` ends a
    line (:func:`split_source_lines`) so a NEL inside a legacy string literal
    does not count as a line of its own.
    """
    return "\n".join(
        line
        for line in (ln.removesuffix("\r") for ln in split_source_lines(text))
        if not line.lstrip().startswith(_GENERATED_STAMP_PREFIX)
    )


def filename_component(name: str) -> str:
    """*name* reduced to one safe path component.

    Annotation symbols come from project metadata and reverse-engineering
    comments, so they are untrusted: joining one into a path as-is lets a
    ``../../..`` or absolute name escape the run directory (or a leading ``-``
    read as an option).  Everything outside ``[A-Za-z0-9._@-]`` becomes ``_``,
    leading dots and dashes are stripped, and a name that sanitizes to nothing
    falls back to a stable digest of the original.

    NFC first: the substitution below deletes non-ASCII either way, but it
    deletes a *different* amount for each spelling of one name, so without it
    ``"CAFÉ"`` and ``"CAFE\\u0301"`` (the same DLL named from a PE import table
    and from a ``.pat`` file on a decomposing volume) land in two headers.

    A stem that is a DOS device name gets an underscore: Win32 resolves
    ``CON``, ``con.json`` and ``nul.best.c`` to the device, not to a file, so
    a symbol or module called ``NUL`` would make the write succeed and discard
    the bytes.  A caller appending its own suffix (``{symbol}.best.c``) does
    not clear the reservation, so the check belongs here, not at each writer.
    """
    name = unicodedata.normalize("NFC", name)
    cleaned = _FILENAME_COMPONENT_RE.sub("_", name).lstrip(".-")
    cleaned = cleaned[:_FILENAME_COMPONENT_MAX_CHARS].rstrip("._-")
    if cleaned.partition(".")[0].upper() in _RESERVED_WINDOWS_STEMS:
        cleaned = f"_{cleaned}"
    if not cleaned:
        digest = hashlib.sha256(name.encode("utf-8", "surrogateescape")).hexdigest()[:16]
        return f"sym_{digest}"
    return cleaned


def library_header_name(module: str) -> str:
    """The ``library_<module>.h`` file name for *module*.

    One derivation for every writer that appends IAT/LIBRARY entries to a
    library header (:mod:`rebrew.splat_config`, :mod:`rebrew.identify_library`).
    The module comes from a PE import table or a ``.pat`` stem, so it goes
    through :func:`filename_component`; building the name by hand
    (``f"library_{module.lower()}.h"``) splits one DLL's annotations across two
    headers as soon as the stem is not ASCII, and a ``../`` stem escapes the
    reversed dir.
    """
    return f"library_{filename_component(module.lower())}.h"


def _set_mode_quietly(filepath: Path, mode: int) -> None:
    """chmod *filepath* to *mode*, reporting rather than swallowing a failure."""
    try:
        os.chmod(filepath, mode)
    except OSError as exc:
        logger.warning("could not set mode %s on %s: %s", oct(mode), filepath, exc)


def atomic_write_text(
    filepath: Path,
    text: str,
    encoding: str = "utf-8",
    errors: str = "strict",
    mode: int = _DEFAULT_FILE_MODE,
    lenient: bool = False,
) -> None:
    """Write text to a file atomically to prevent corruption on crash.

    Strategy: write to a sibling .tmp file, then ``os.replace()`` (atomic
    on both POSIX and Windows/NTFS).  If *any* exception occurs —
    including KeyboardInterrupt — the temp file is cleaned up so we never
    leave partial writes at the target path.

    The temp name carries the writer's pid and thread id so two concurrent
    writers of the same target (e.g. ``rebrew verify`` and ``rebrew test``
    both promoting STATUS into ``rebrew-functions.toml``) cannot interleave
    into one shared scratch file and publish a spliced result.  This makes
    each write self-contained; it does not serialise read-modify-write
    cycles, so a genuine last-writer-wins update is still possible.

    Encoding up front keeps the caller's line endings byte-exact (no
    ``newline`` translation) and lets the write reuse
    :func:`atomic_write_bytes`, which owns the byte-identical short-circuit
    and the temp-file dance.  An unencodable string raises
    ``UnicodeEncodeError`` before any file is touched.

    *errors* mirrors :meth:`pathlib.Path.write_text`: use
    ``\"surrogateescape\"`` when *text* came from :func:`read_compile_source`
    so lone surrogates from legacy bytes round-trip instead of raising.
    *lenient* encodes through :func:`encode_source_text` instead, for a
    write-back into a file whose own bytes *text* may not cover.

    *mode* is the permission the temp file is created with, and therefore the
    mode ``os.replace`` installs.  Pass a restrictive one for a file holding a
    secret (a decomp.me claim token ledger): creating the temp 0644 and
    chmod-ing afterwards leaves the secret readable by every local user for the
    duration of the write, and world-readable for good if the process dies
    between the two calls.  Creating it restrictive also tightens a file a
    previous run left at the default, since the replacement inode carries *mode*.
    """
    data = encode_source_text(text, encoding) if lenient else text.encode(encoding, errors=errors)
    atomic_write_bytes(filepath, data, mode=mode)
    # Drop any stale path+mtime entries so a same-ns rewrite cannot serve
    # pre-write content to a later reader in this process.
    try:
        resolved = str(filepath.resolve())
    except OSError:
        resolved = ""
    if resolved:
        with _SOURCE_TEXT_MEMO_LOCK:
            for memo_key in tuple(_SOURCE_TEXT_MEMO_BY_PATH.get(resolved, ())):
                _memo_drop(memo_key)


def encode_source_text(text: str, encoding: str) -> bytes:
    """Encode *text* for *encoding* so a legacy source survives the write-back.

    ``surrogateescape`` first, which round-trips the lone surrogates
    :func:`read_compile_source` produces for bytes the file never held as
    UTF-8.  A code point the target encoding has no byte for still raises
    there: U+FFFD from :func:`read_source_text`'s lossy decode, a Hebrew
    letter in a Shift-JIS source, or a compiler diagnostic that quoted one.
    Those fall back to ``?`` per character, because the write is an edit
    placement into a file that already holds those bytes, and losing one
    character beats losing the edit.
    """
    try:
        return text.encode(encoding, errors="surrogateescape")
    except UnicodeEncodeError:
        return text.encode(encoding, errors="replace")


def atomic_write_bytes(filepath: Path, data: bytes, mode: int = _DEFAULT_FILE_MODE) -> None:
    """Byte counterpart of :func:`atomic_write_text`.

    Writes to a sibling ``.<pid>.<tid>.<monotonic>.tmp`` then ``os.replace()``s, so a
    crash or disk-full mid-write never leaves a truncated binary at the
    target path (e.g. a postlinked or reassembled PE).  The temp file is
    cleaned up on any failure; the original exception is always re-raised.

    When the on-disk bytes already match *data*, the replace is skipped so a
    no-op re-run (a second ``postlink`` of an already-converged binary, a
    report sidecar rebuild) does not bump mtime.  Same contract as
    :func:`atomic_write_text`, including the read-only-directory message.

    *mode* is as in :func:`atomic_write_text`; on the short-circuit path the
    existing file is chmod-ed to it, so a file a previous run left wider is
    tightened even when this run's bytes are unchanged.
    """
    filepath.parent.mkdir(parents=True, exist_ok=True)
    if filepath.is_file():
        try:
            if filepath.read_bytes() == data:
                _set_mode_quietly(filepath, mode)
                return
        except OSError:
            pass
    with _atomic_replace(filepath) as tmp_path:
        # O_EXCL: a name planted in the target directory as a symlink must not
        # be followed, or the write lands on the link's target.
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
        # Durability comes from _atomic_replace's best-effort _fsync_path on
        # the temp path, which also syncs the parent directory.  A bare
        # fsync() on the write fd would be redundant there and would fail the
        # whole write on a mount that refuses it (FUSE, virtiofs, some
        # overlayfs and NFS configurations answer EINVAL/ENOTSUP), which is a
        # successful write reported as a crash.


def atomic_write_locked(filepath: Path | str, text: str, encoding: str = "utf-8") -> None:
    """Write *text* atomically, leaving the file read-only (mode 0444).

    The metadata write-lock discipline for tool-owned files
    (``rebrew-functions.toml``, ``rebrew-data.toml``, the binsync
    ``functions/*.toml`` / ``global_vars.toml`` / ``structs/*.toml``
    exports): **chmod writable before touching, write, chmod read-only
    after**.  Direct edits by hand fail with
    Permission denied; the only sanctioned path is the CLI, which chmods
    writable, updates, and re-locks.

    If the write fails after the chmod-writable step, the existing file is
    re-locked to 0444 before the exception propagates — otherwise a disk-full
    or interrupt would leave the tool-owned store world-writable.
    """
    filepath = Path(filepath)
    with contextlib.suppress(OSError):
        os.chmod(filepath, 0o644)  # chmod before touching the file
    try:
        atomic_write_text(filepath, text, encoding=encoding)
    except BaseException:
        # Re-lock whatever is still at the path (the pre-write content when
        # atomic_write_text rolled back the temp file).  Missing path is fine
        # on a first-write failure — suppress covers that.
        _relock_quietly(filepath)
        raise
    # os.replace installs the temp's 0644 inode, so this chmod is the only
    # thing restoring the 0444 invariant; a silent failure would leave a
    # tool-owned store world-writable for the rest of the run.
    _relock_quietly(filepath)


def _relock_quietly(filepath: Path) -> None:
    """chmod *filepath* to 0444, reporting rather than swallowing a failure."""
    try:
        os.chmod(filepath, 0o444)
    except FileNotFoundError:
        return  # first-write failure: nothing at the path to re-lock
    except OSError as exc:
        logger.warning("could not re-lock %s to 0444: %s", filepath, exc)


def fold_ident(value: str) -> str:
    """Case-insensitive identity of a user-supplied name: NFC, then casefold.

    ``str.lower`` and ``str.upper`` disagree on sharp s
    (``"straße".lower()`` is ``"straße"``, ``"STRASSE".lower()`` is
    ``"strasse"``, and both ``.upper()`` to ``"STRASSE"``). Neither
    unifies NFC ``é`` with NFD ``e\\u0301``. Module markers and symbol
    names use this fold so those spellings compare as one name.
    """
    return unicodedata.normalize("NFC", value).casefold()


def ascii_slug(value: str) -> str:
    """*value* reduced to the ASCII a C identifier, path, or target name can hold.

    ``casefold`` first, then NFKD, then drop what is not ASCII.  The order
    matters: casefold expands sharp s (``"straße"`` -> ``"strasse"``) and
    NFKD splits the accents off ``é`` so the base letter survives
    (``"Café"`` -> ``"cafe"``, not ``"caf"``).  Dropping non-ASCII without
    decomposing first silently deletes letters, so ``"Über"`` would collapse
    to ``"ber"`` and ``"日本語"`` to ``""``.

    Returns ``""`` when nothing ASCII is left (CJK, emoji, or a name written
    entirely in a script with no Latin decomposition); callers decide the
    fallback rather than receiving a name that is neither the input nor a
    prefix of it.
    """
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    return decomposed.encode("ascii", "ignore").decode("ascii")


def preset_module_key(name: str) -> str:
    """Key spelling for ``cflags_presets`` and origin lists.

    NFC, then ``upper``, which is what ``rebrew cfg`` writes
    (``SERVER``, ``STRASSE``). Lookups must use this function:
    :func:`fold_ident` would miss a stored ``SERVER`` key.
    """
    return unicodedata.normalize("NFC", name).upper()


def strip_body(prototype: str) -> str:
    """Return the function signature without the body (everything before ``{``).

    ``annotation.prototype`` includes the full C definition including its body.
    BinSync's ``[header].type`` expects only the declaration/signature line.
    Brace detection is quote-aware — a ``{`` inside a string literal (e.g.
    ``const char *s = "{"``) must not be mistaken for the body delimiter.
    """
    in_str = False
    escaped = False
    for i, ch in enumerate(prototype):
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            return prototype[:i].strip()
    return prototype.strip()


# Free-slot search bound for preserve_corrupt; see the loop there.
_CORRUPT_SLOT_ATTEMPTS = 10_000


def preserve_corrupt(path: Path) -> Path:
    """Move an unparseable file aside to ``<name>.corrupt`` and return the new path.

    Callers that recover from a parse failure by rebuilding the document from
    scratch would otherwise overwrite the whole store (every function's STATUS,
    CFLAGS and notes) because of one bad byte.  Renaming first keeps the
    original recoverable.  Raises ``OSError`` if preservation fails so callers
    cannot overwrite a store that has not been backed up.
    """
    backup = path.with_name(path.name + ".corrupt")
    if backup.exists():
        # Avoid clobbering a previous .corrupt snapshot — keep both.
        # Second-granularity wall-clock suffixes collide within the same
        # second and again after an NTP step-back; os.replace would then
        # overwrite the earlier salvage.  Nanoseconds plus a free-slot
        # bump stay unique across both events.
        suffix = time.time_ns()
        # Bound the free-slot search: an unbounded ``exists()`` loop would
        # hang if every candidate is somehow occupied (full directory /
        # adversarial stubs).  A few thousand bumps past the ns stamp is
        # already impossible under normal FS conditions.
        for _ in range(_CORRUPT_SLOT_ATTEMPTS):
            candidate = path.with_name(f"{path.name}.{suffix}.corrupt")
            if not candidate.exists():
                backup = candidate
                break
            suffix += 1
        else:
            raise OSError(
                f"cannot preserve corrupt store {path}: no free .corrupt slot "
                f"after {_CORRUPT_SLOT_ATTEMPTS} attempts"
            )
    os.replace(path, backup)
    return backup


#: Directory under a project's scratch state where :func:`source_backup` keeps
#: the pre-run copy of a source file a sweep is about to rewrite in place.
SOURCE_BACKUP_DIRNAME = "source-backups"


@contextlib.contextmanager
def source_backup(
    path: Path,
    text: str,
    encoding: str,
    backup_dir: Path,
    *,
    label: str = "",
    keep: bool = False,
) -> Iterator[Path | None]:
    """Hold *text*, the content of *path* before an in-place rewrite, on disk for the span.

    A sweep scores candidates by compiling them out of the real ``.c``, so the
    run rewrites that file many times and puts *text* back on its normal and
    exception paths.  A catchable signal gets the same treatment, but SIGKILL,
    an OOM kill, a power cut, or a stopped container runs no Python at all: the
    file is left holding whichever candidate was last scored, and hand-written
    work that exists nowhere else is lost with no record of how it got there.
    Writing the pre-run bytes under *backup_dir* before the first destructive
    write is what survives that; the in-process restore cannot.

    The backup is removed when the body returns -- the source is then in its
    intended final state -- and kept when the body raises, with its path
    logged.  *keep* holds the copy after a clean return too, for a one-shot
    rewrite that has no in-process restore: the strip in
    :mod:`rebrew.migrate_markers` has no second chance, so the pre-migration
    bytes stay on disk where the operator can put them back.
    A caller that can be killed without warning should print the
    yielded path before its first destructive write, since a recovery copy
    nothing points at is not a recovery path.  The writer's pid is in the file
    name, so two sweeps of one symbol cannot overwrite each other's copy and a
    run that was killed leaves its predecessor's alone.

    Yields ``None`` when the backup cannot be written, so a caller that
    announces a recovery copy names a file that exists.  The failure is logged
    and the body still runs: the in-process restore covers the common case, and
    refusing to sweep would trade a narrow window for no work at all.
    """
    backup_dir.mkdir(parents=True, exist_ok=True)
    stem = filename_component(label or path.stem)
    backup_path = backup_dir / f"{path.name}.{stem}.{os.getpid()}.orig"
    try:
        atomic_write_text(backup_path, text, encoding=encoding)
    except OSError:
        logger.warning(
            "could not back up %s to %s before rewriting it in place;"
            " the in-process restore still runs, but an uncatchable kill loses it",
            path,
            backup_path,
            exc_info=True,
        )
        yield None
        return
    try:
        yield backup_path
    except BaseException:
        logger.warning("kept the pre-run copy of %s at %s", path, backup_path)
        raise
    if keep:
        logger.info("kept the pre-run copy of %s at %s", path, backup_path)
        return
    with contextlib.suppress(OSError):
        backup_path.unlink()


def load_toml_for_write(path: Path, description: str) -> TOMLDocument:
    """Parse *path* for a read-modify-write cycle, tolerating a corrupt store.

    Returns an empty document if the file is missing.  If it exists but cannot
    be parsed, the original is moved aside via :func:`preserve_corrupt` (so the
    caller's subsequent write does not silently discard every other entry) and
    an empty document is returned.  A failure to read or preserve the store
    propagates instead: writing a fresh document would destroy metadata the
    caller never saw.

    *description* names the store in the warning (e.g. ``"metadata"``).
    """
    try:
        return tomlkit.parse(read_toml_text(path))
    except FileNotFoundError:
        return tomlkit.document()
    except InternalParserError:
        raise
    except (ParseError, UnicodeDecodeError) as exc:
        backup = preserve_corrupt(path)
        logger.warning(
            "Failed to parse %s %s (%s); preserved as %s, starting fresh",
            description,
            path,
            exc,
            backup,
        )
        return tomlkit.document()


def load_toml_for_write_strict(path: Path, description: str) -> TOMLDocument:
    """Parse *path* for a read-modify-write cycle, refusing a corrupt store.

    Identical to :func:`load_toml_for_write` for a readable or missing file.
    An existing file that cannot be parsed raises ``ValueError`` instead of
    being moved aside: that store holds state the caller never saw (every
    other entry's STATUS, blockers, notes), so starting a fresh document
    replaces the whole file with the one field being written.  Recovering from
    the ``.corrupt`` sidecar is a decision the operator makes, not the writer.

    *description* names the store in the message (e.g. ``"metadata"``).
    """
    try:
        return tomlkit.parse(read_toml_text(path))
    except FileNotFoundError:
        return tomlkit.document()
    except InternalParserError:
        raise
    except (ParseError, UnicodeDecodeError) as exc:
        raise ValueError(f"refusing to overwrite unparseable {description} {path}: {exc}") from exc


@contextlib.contextmanager
def file_handle_lock(lock_fh: IO[str], *, shared: bool = False) -> Iterator[None]:
    """Hold an advisory ``flock`` on an open file handle.

    On Windows the lock is taken with ``msvcrt.locking``, which raises once
    its built-in retry window expires.  That failure propagates: running the
    body unlocked lets a second process interleave its read-modify-write of
    the metadata store and silently drop this one's STATUS promotion, which
    is exactly the loss the lock exists to prevent.
    """
    if fcntl is not None:
        fcntl.flock(lock_fh, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
    else:
        import msvcrt

        lock_fh.seek(0)
        try:
            msvcrt.locking(lock_fh.fileno(), msvcrt.LK_LOCK, 1)
        except OSError as exc:
            raise OSError(
                f"could not lock {getattr(lock_fh, 'name', '<handle>')}: {exc}; "
                "another rebrew process is holding the write lock"
            ) from exc
    try:
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
        else:
            import msvcrt

            lock_fh.seek(0)
            try:
                msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError as exc:
                # The lock is released when the descriptor closes either way;
                # surfacing this in the caller's finally would mask the
                # exception that made the body unwind.
                logger.debug("unlock failed on %s: %s", getattr(lock_fh, "name", "<handle>"), exc)


@contextlib.contextmanager
def file_lock(lock_path: Path, *, shared: bool = False) -> Iterator[None]:
    """Hold an advisory ``flock`` on *lock_path* (created if absent).

    Cross-process only: ``flock`` does not exclude other threads that open
    their own fd in the same process, so callers pair it with a thread lock.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a", encoding="utf-8") as lock_fh, file_handle_lock(lock_fh, shared=shared):
        yield


def safe_shlex_split(command: str) -> list[str]:
    """Split a shell command string, falling back to str.split() on parse errors.

    Handles unbalanced quotes in compiler commands gracefully.
    """
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _kill_process_group(proc: subprocess.Popen[Any]) -> None:
    """Terminate the process group (POSIX) or process (Windows) safely."""
    if hasattr(os, "killpg") and hasattr(signal, "SIGKILL"):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
    else:
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.kill()


def _descendant_pids(pid: int) -> set[int]:
    """PIDs whose parent chain reaches *pid*, from ``/proc`` (empty if absent).

    Taken before the group kill: a grandchild that already called ``setsid``
    is still listed under its parent, and after the parent dies its ppid is
    1 and the link is gone.
    """
    proc_root = Path("/proc")
    if pid <= 1 or not proc_root.is_dir():
        return set()
    children: dict[int, list[int]] = {}
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return set()
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            # ``pid (comm) state ppid`` — comm may contain spaces and parens,
            # so the last ``)`` is the end of the comm field.
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
            tail = stat.rsplit(")", 1)[1].split()
            child = int(entry.name)
            ppid = int(tail[1])
        except (OSError, IndexError, ValueError):
            continue
        if child <= 1 or ppid <= 0:
            continue
        children.setdefault(ppid, []).append(child)
    out: set[int] = set()
    stack = list(children.get(pid, []))
    while stack:
        child = stack.pop()
        if child in out or child == pid:
            continue
        out.add(child)
        stack.extend(children.get(child, []))
    return out


def _kill_pids(pids: set[int]) -> None:
    """SIGKILL each pid; a missing process is already gone."""
    if not hasattr(signal, "SIGKILL"):
        return
    for pid in pids:
        if pid <= 1:
            continue
        with contextlib.suppress(ProcessLookupError, OSError):
            os.kill(pid, signal.SIGKILL)


def _release_captured_pipes(proc: subprocess.Popen[Any]) -> None:
    """Close captured stdio so a surviving writer cannot pin ``communicate``.

    ``communicate`` waits for EOF. A helper that escaped both the process
    group and the descendant snapshot, and kept the pipe write end, never
    delivers that EOF — another ``communicate()`` then blocks for the
    helper's lifetime.
    """
    for stream in (proc.stdout, proc.stderr, proc.stdin):
        if stream is None:
            continue
        with contextlib.suppress(OSError):
            stream.close()


def _stop_process_tree(proc: subprocess.Popen[Any]) -> None:
    """Kill *proc*'s session and descendants snapshotted before the signal."""
    descendants = _descendant_pids(proc.pid)
    _kill_process_group(proc)
    _kill_pids(descendants)
    with contextlib.suppress(ProcessLookupError, OSError):
        proc.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=1)


def run_process_group(
    cmd: Sequence[str], *, timeout: float, **popen_kwargs: Any
) -> subprocess.CompletedProcess[Any]:
    """``subprocess.run(cmd, timeout=...)`` that kills the whole process group.

    Plain ``subprocess.run`` SIGKILLs only the direct child on timeout, so a
    driver's grandchildren (gcc's ``cc1``/``as``, ``xvfb-run``'s Xvfb and
    wine, a wrapper script's compiler) are orphaned and keep running.  The
    child here leads its own session; on timeout the group is killed, any
    descendant that already left the session is signalled from a ``/proc``
    snapshot, and the child is reaped before :class:`subprocess.TimeoutExpired`
    is raised.  A writer that still holds a captured pipe cannot pin the
    caller: the read ends are closed instead of waiting for its EOF.
    ``popen_kwargs`` take ``subprocess.run``'s keywords except ``check``;
    ``input`` is written to the child's stdin.  Pass ``capture_output=True``
    to collect output.

    The child is managed explicitly rather than through ``Popen.__exit__``,
    which calls ``wait()`` with no timeout: on the wedged-writer case the
    timeout path exists to survive, that ``wait()`` re-blocks forever.
    """
    stdin_input = popen_kwargs.pop("input", None)
    if popen_kwargs.pop("capture_output", False):
        popen_kwargs["stdout"] = subprocess.PIPE
        popen_kwargs["stderr"] = subprocess.PIPE
    if stdin_input is not None and popen_kwargs.get("stdin") is None:
        popen_kwargs["stdin"] = subprocess.PIPE
    if popen_kwargs.get("text") or popen_kwargs.get("universal_newlines"):
        popen_kwargs.setdefault("encoding", "utf-8")
        popen_kwargs.setdefault("errors", "replace")
    # Not a `with`: see the docstring.  Every non-success path below calls
    # `_stop_process_tree`, which kills the group and reaps with a bounded
    # wait; the success path is already reaped by `communicate`.
    proc = subprocess.Popen(list(cmd), start_new_session=True, **popen_kwargs)
    try:
        stdout, stderr = proc.communicate(stdin_input, timeout=timeout)
    except subprocess.TimeoutExpired:
        _stop_process_tree(proc)
        # Drain output the kill left in the pipe.  A short timeout covers
        # a writer the snapshot missed; closing the read ends then lets
        # the caller return instead of blocking on that writer.
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            _stop_process_tree(proc)
            _release_captured_pipes(proc)
        raise
    except BaseException:
        _stop_process_tree(proc)
        raise
    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)


@contextlib.contextmanager
def interruptible_pool(max_workers: int) -> Iterator["concurrent.futures.ThreadPoolExecutor"]:
    """A worker pool whose exit does not block on a BaseException.

    ``ThreadPoolExecutor.__exit__`` calls ``shutdown(wait=True)``, so a
    ``KeyboardInterrupt`` (or a ``typer.Exit``) raised while consuming
    ``executor.map`` surfaces only after *every other* worker has run to
    completion.  Each worker here is a GA or a container compile bounded by
    ``--timeout-min``, so Ctrl+C appears to hang for minutes per in-flight
    item, and the ``exit_130_on_interrupt`` contract in :mod:`rebrew.cli`
    never gets its turn.

    On an exception the queued-but-unstarted work is cancelled and the
    in-flight workers are left to finish on their own (the interpreter
    joins them at exit); the pool is still shut down on a clean exit.
    """
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    try:
        yield executor
    except BaseException:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)


def watch_files(
    paths: list[Path],
    retest: Callable[[], None],
    interval: float = 1.0,
    path_provider: Callable[[], list[Path]] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> None:
    """Poll *paths* and call *retest* whenever any file's mtime changes.

    Runs until Ctrl+C.  A failed re-run (``BaseException`` other than
    ``KeyboardInterrupt``, e.g. ``typer.Exit`` from ``error_exit``) is
    reported and swallowed so the loop keeps watching for a fix.  Files that
    are deleted or not yet created are tolerated (editors that
    delete-and-rename keep working).

    With *path_provider*, the watched set is re-resolved every poll — new
    files created during the session (e.g. a ``rebrew skeleton`` generating a
    fresh ``.c`` while ``verify --watch`` runs) are picked up instead of the
    loop silently stopping to cover them.

    *sleep* is the poll's only time source: a replay passes a stepper that
    advances a virtual clock, so the same sequence of edits is observed
    without the run waiting on wall-clock time.  Left unset it reads
    :func:`time.sleep` per poll, so a patched clock is still honoured.
    """

    nap = sleep if sleep is not None else time.sleep

    def _current_paths() -> list[Path]:
        return path_provider() if path_provider is not None else paths

    def _stat_keys() -> dict[Path, tuple[int, int, int]]:
        """``(mtime_ns, size, ino)`` per watched path.

        mtime alone misses an edit that preserves it: ``cp -p``, a
        ``git checkout`` of a restored file, and a coarse-timestamp
        filesystem all leave mtime_ns and size equal while the content
        changes, and the run then never re-tests.  Same triple every
        stat-keyed memo in the tree carries.
        """
        out: dict[Path, tuple[int, int, int]] = {}
        for p in _current_paths():
            try:
                st = p.stat()
            except OSError:
                continue
            out[p] = (st.st_mtime_ns, st.st_size, st.st_ino)
        return out

    last = _stat_keys()
    console.print(
        f"[dim]Watching {len(last)} file(s) — re-run on every save (Ctrl+C to stop)...[/dim]"
    )
    try:
        while True:
            nap(interval)
            current = _stat_keys()
            if current == last:
                continue
            last = current
            try:
                retest()
            except BaseException as exc:  # keep watching after a failed run
                if isinstance(exc, KeyboardInterrupt):
                    raise
                console.print(
                    f"[dim]Run failed ({exc.__class__.__name__}) — waiting for a fix...[/dim]"
                )
    except KeyboardInterrupt:
        console.print("[dim]Watch stopped.[/dim]")


# ---------------------------------------------------------------------------
# HTTP response helpers
# ---------------------------------------------------------------------------


#: Transient HTTP statuses a remote compile service may be retried on after a
#: backoff.  Shared by ``recompile_client`` and ``decompme`` so the two
#: clients cannot drift on which failures are worth another attempt.
RETRYABLE_HTTP_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})

#: Base delay (seconds) for exponential backoff between retryable attempts,
#: and the ceiling that keeps a long backoff bounded.
RETRY_BACKOFF_BASE = 0.25
RETRY_BACKOFF_CAP = 8.0

#: First exponent whose delay already reaches ``RETRY_BACKOFF_CAP``.  Every
#: attempt past it waits the cap, so clamping the exponent there keeps a large
#: attempt from overflowing the float exponentiation before ``min`` can cap it.
RETRY_BACKOFF_CAP_EXPONENT = next(
    n for n in range(64) if RETRY_BACKOFF_BASE * (2.0**n) >= RETRY_BACKOFF_CAP
)


def retry_backoff_delay(attempt: int) -> float:
    """Seconds to wait before retry *attempt* (zero-based) of a retryable call.

    The one backoff policy the service clients share, so ``recompile_client``
    and ``decompme`` cannot drift on how hard they hammer a recovering
    service: ``delay = min(RETRY_BACKOFF_BASE * 2**attempt, RETRY_BACKOFF_CAP)``.
    """
    exponent = min(attempt, RETRY_BACKOFF_CAP_EXPONENT)
    return min(RETRY_BACKOFF_BASE * (2.0**exponent), RETRY_BACKOFF_CAP)


#: How much of a failed attempt's message reaches a retry log line.  The
#: message carries a slice of a remote response body, and a warning is read on
#: a terminal, not diffed.
RETRY_LOG_MESSAGE_CHARS = 300


def retry_log_detail(exc: BaseException) -> str:
    """*exc* as one bounded, terminal-safe line for a retry warning.

    The one way ``recompile_client`` and ``decompme`` quote a failed
    attempt, so their backoff logs cannot drift on how much of a hostile
    response body reaches the terminal.  ``llm_seed`` does not use it: that
    warning has to redact the API key out of the text first.
    """
    return untrusted_literal(exc)[:RETRY_LOG_MESSAGE_CHARS]


def close_response(resp: Any) -> None:
    """Release an HTTP response so its connection returns to the pool.

    Real ``httpx.Response`` objects must be closed on every exit path or a
    reused client drains its pool slots until GC; injected test stand-ins
    may omit ``.close``, and a close failure must never mask the request's
    own result or exception.
    """
    close = getattr(resp, "close", None)
    if callable(close):
        with contextlib.suppress(Exception):
            close()


def strip_comment_blocks(text: str) -> str:
    """Remove C ``/* ... */`` comment blocks from *text*, keeping code lines.

    Source preambles often interleave large Ghidra decompilation-reference
    comment blocks with real code (typedefs, externs, dllimport decls).
    Repeating those comment blocks into every merged/split output file bloats
    round-trips ~17x, and a naive line-union of multiple preambles can leave
    the ``/* */`` nesting malformed so the output no longer compiles.

    Quote-aware: ``/*``/``*/`` inside string literals are not treated as
    comment delimiters, so ``const char *s = "a/*b";`` survives intact.
    Also drops orphaned comment-continuation lines (``* ...`` outside any
    block) produced by such unions, and keeps code on either side of a
    comment — same-line (``a = b /* c */ + d;``) and after a multi-line
    block's close (``/* a\n * b\n */ int x;``).  Returns the code with
    blank-line runs collapsed and no trailing blank lines.

    Only ``\n`` ends a line (:func:`split_source_lines`): ``str.splitlines``
    would also break on NEL, LS, PS, VT, and FF, which are legal inside a C
    string literal, so the join below would turn each of them into a newline.
    The terminator is dropped per line, so the returned text is LF-separated
    whatever the input used; callers join it with :func:`source_newline` in the
    target file's own ending.
    """
    out: list[str] = []
    in_block = False
    in_string_global = ""  # the open quote character, "" outside a literal
    for line in (ln.removesuffix("\r") for ln in split_source_lines(text)):
        stripped = line.strip()
        if stripped == "*/":
            # Closes an open comment block (or a harmless orphan).
            # Also reset global string state — we are outside any string on a new line
            # after a block comment close; the per-line scanner handles the rest.
            in_block = False
            in_string_global = ""
            continue
        if stripped.startswith("* ") and not in_block:
            # Orphaned comment-continuation lines (malformed /* */ nesting).
            # Inside a block, a `* ` prefix is just comment content — the line
            # must still go through the scanner so a trailing `*/` (possibly
            # followed by code) is honoured instead of leaving the block open.
            continue
        buf: list[str] = []
        in_string = in_string_global
        # Handle single-quoted char literals and multi-line strings: carry
        # in_string across lines when the previous line left a string open
        # without a closing quote.
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            if in_block:
                # Inside a comment: it ends at the first literal */ (no
                # string parsing inside comments per C semantics).
                close = line.find("*/", i)
                if close == -1:
                    i = n  # still in block — drop the rest of this line
                    continue
                in_block = False
                i = close + 2
                continue
            if in_string:
                buf.append(ch)
                if ch == "\\" and i + 1 < n:
                    buf.append(line[i + 1])
                    i += 2
                    continue
                if ch == in_string:
                    in_string = ""
                i += 1
                continue
            if line.startswith("//", i):
                # Line comment runs to end of line — a `/*` inside it must
                # not open a block (e.g. `int x; // /* note`).
                i = n
                continue
            if line.startswith("/*", i):
                rest = line[i + 2 :]
                close = rest.find("*/")
                if close != -1:
                    # Resume after the closing */ — trailing code and any
                    # further comments/strings on the line are kept.
                    i = i + 2 + close + 2
                else:
                    in_block = True
                    i = n
                continue
            buf.append(ch)
            if ch in ('"', "'"):
                in_string = ch
            i += 1
        in_string_global = in_string
        joined = "".join(buf)
        # Keep blank lines (collapse handles runs) and any code; drop
        # comment-only lines entirely.
        if joined.strip() or not line.strip():
            out.append(joined)
    # Collapse blank-line runs (comment removal leaves gaps) and drop any
    # leading blanks left by comment-only lines.
    result: list[str] = []
    for line in out:
        if not line.strip() and (not result or not result[-1].strip()):
            continue
        result.append(line)
    while result and not result[-1].strip():
        result.pop()
    return "\n".join(result)


def rel_display_path(filepath: Path, base_dir: Path | None = None) -> str:
    """Return a display-friendly relative path for a source file.

    If *base_dir* is provided, returns the path relative to it (e.g.
    ``"game/pool_free.c"`` for nested dirs, or ``"pool_free.c"`` for flat
    layouts).  A file outside *base_dir* gets a ``..``-relative path — the
    bare filename would resolve to the wrong location from the base dir.
    Falls back to ``filepath.name`` if even that is impossible (cross-drive
    on Windows) or no *base_dir* is given.

    Always uses forward slashes so the same relative key works in metadata,
    JSON reports, and set membership on every host (``str(Path)`` would emit
    backslashes on Windows and break matching against POSIX-stored paths).
    """
    if base_dir is not None:
        try:
            return filepath.relative_to(base_dir).as_posix()
        except ValueError:
            try:
                return Path(os.path.relpath(filepath, base_dir)).as_posix()
            except ValueError:  # cross-drive on Windows
                return filepath.name
    return filepath.name


#: ASCII digit sets the literal parsers accept, keyed by base.
_BASE_DIGITS = {8: "01234567", 10: "0123456789", 16: "0123456789abcdefABCDEF"}


def _parse_ascii_int(text: str, base: int) -> int:
    """Parse *text* as a base-*base* integer, rejecting ``int()``'s leniencies.

    ``int()`` also accepts embedded underscores and any Unicode decimal digit,
    so a config value or a disassembly operand such as ``"1_0"`` or
    ``"١٢"`` parses to a number no writer meant.  Only ASCII digits of *base*
    count; anything else is a :class:`ValueError`.
    """
    digits = _BASE_DIGITS.get(base)
    if digits is None or not text or not all(ch in digits for ch in text):
        raise ValueError(f"not a base-{base} integer: {text!r}")
    return int(text, base)


def parse_int_literal(text: str, *, base: int = 10) -> int:
    """Parse an integer literal for config, addresses, and disassembly text.

    A ``0x``/``0X`` prefix selects base 16; anything else uses *base* (decimal
    by default), including a leading zero (``010`` is ten).  Raises
    ``ValueError`` on a malformed literal, so callers that want a fallback can
    catch it, and callers that must fail loud (the CLI's ``parse_va``) let it
    propagate.  Only ASCII digits are accepted; see :func:`_parse_ascii_int`.

    C source constants (octal ``010``, a ``u``/``l`` suffix) go through
    :func:`parse_c_integer_literal` instead.  ``int(s, 0)`` is not that
    parser: on Python 3.14 it rejects the leading zero and the caller stores
    zero.
    """
    stripped = text.strip()
    sign = -1 if stripped.startswith("-") else 1
    s = stripped[1:] if stripped.startswith(("+", "-")) else stripped
    if s[:2].lower() == "0x":
        if not s[2:]:
            raise ValueError(f"not an integer literal: {stripped!r}")
        return sign * _parse_ascii_int(s[2:], 16)
    return sign * _parse_ascii_int(s, base)


def parse_c_integer_literal(text: str) -> int:
    """Parse one C integer constant.

    Accepts an optional sign, a ``0x`` hex form, a leading-zero octal form
    (``010`` is eight), a decimal form, and a trailing ``u``/``l`` suffix.
    A leading-zero token that is not valid octal (``08``) is the zero-padded
    decimal of that magnitude: C rejects it, and dropping the bound sized
    the array as one element.  Raises ``ValueError`` when *text* is not an
    integer constant, including for a non-ASCII digit: ``int()`` would read
    ``"١٢"`` as twelve, and a bound nobody wrote is not a bound.
    """
    body = text.strip()
    if not body or body[0] == "'":
        raise ValueError(f"not a C integer constant: {text!r}")
    while body and body[-1] in "uUlL":
        body = body[:-1]
    if not body:
        raise ValueError(f"not a C integer constant: {text!r}")
    sign = -1 if body[0] == "-" else 1
    if body[0] in "+-":
        body = body[1:].strip()
    if not body:
        raise ValueError(f"not a C integer constant: {text!r}")
    if body[:2].lower() == "0x":
        if len(body) == 2:
            raise ValueError(f"not a C integer constant: {text!r}")
        return sign * _parse_ascii_int(body[2:], 16)
    if len(body) > 1 and body[0] == "0" and body[1] in _BASE_DIGITS[10]:
        try:
            return sign * _parse_ascii_int(body, 8)
        except ValueError:
            return sign * _parse_ascii_int(body, 10)
    return sign * _parse_ascii_int(body, 10)
