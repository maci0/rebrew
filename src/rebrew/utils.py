"""Shared utilities for rebrew."""

import contextlib
import logging
import os
import shlex
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import tomlkit
from tomlkit import TOMLDocument

logger = logging.getLogger(__name__)

# The rebrew package's own vendored toolchains (toolchain/msvc/5.0-win32, toolchain/watcom/2.0-win32,
# ...).  Projects resolve compiler paths project-relative first, then fall
# back here so a freshly-inited project works without a local tools/ symlink.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_INSTALL_TOOLS = _REPO_ROOT / "tools"


def find_install_tool(rel: str | Path) -> Path | None:
    """Resolve *rel* (a project-relative ``tools/...`` path) against the
    rebrew install's own vendored tree, or None when absent.

    Used by the config/compile layers so vendored toolchains (MSVC, Watcom,
    Delphi, diec) resolve out of the box; a project-local ``tools/`` symlink
    (via ``rebrew init --link-tools-from``) still takes precedence because
    callers check the project path first.
    """
    p = _REPO_ROOT / rel
    return p if p.exists() else None


#: Candidate MSVC toolchain layouts per profile, best first: the full master
#: (Bin+Include+Lib) then the vendored compile-only mirrors (newer codegen
#: first — docs/TOOLCHAIN.md notes SP3 codegen differs from SP6).  The mirror
#: dirs carry version suffixes (msvc-6.0-sp3-win32/6.6/7.0) while the master keeps the
#: classic names (msvc-6.0-win32/VC98, msvc-7.0-win32), so a machine with only the mirrors
#: must not be handed a broken master path.
_MSVC_LAYOUTS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "msvc6": (
        (
            "toolchain/msvc/6.0-win32/VC98/Bin/CL.EXE",
            "toolchain/msvc/6.0-win32/VC98/Include",
            "toolchain/msvc/6.0-win32/VC98/Lib",
        ),
        ("toolchain/msvc/6.0-sp6-win32/Bin/CL.EXE", "toolchain/msvc/6.0-sp6-win32/Include", ""),
        ("toolchain/msvc/6.0-sp3-win32/Bin/CL.EXE", "toolchain/msvc/6.0-sp3-win32/Include", ""),
    ),
    "msvc7": (
        (
            "toolchain/msvc/7.0-win32/Bin/cl.exe",
            "toolchain/msvc/7.0-win32/Include",
            "toolchain/msvc/7.0-win32/Lib",
        ),
        ("toolchain/msvc/7.0-win32/Bin/cl.exe", "toolchain/msvc/7.0-win32/Include", ""),
    ),
    "msvc700": (
        (
            "toolchain/msvc/7.0-rtm-win32/Vc7/bin/cl.exe",
            "toolchain/msvc/7.0-rtm-win32/Vc7/include",
            "toolchain/msvc/7.0-rtm-win32/Vc7/lib",
        ),
    ),
    "msvc700sp1": (
        (
            "toolchain/msvc/7.0-sp1-win32/Vc7/bin/cl.exe",
            "toolchain/msvc/7.0-sp1-win32/Vc7/include",
            "toolchain/msvc/7.0-sp1-win32/Vc7/lib",
        ),
    ),
    "msvc710": (
        (
            "toolchain/msvc/7.1-win32/Vc7/bin/cl.exe",
            "toolchain/msvc/7.1-win32/Vc7/include",
            "toolchain/msvc/7.1-win32/Vc7/lib",
        ),
    ),
    "msvc710sp1": (
        (
            "toolchain/msvc/7.1-sp1-win32/Vc7/bin/cl.exe",
            "toolchain/msvc/7.1-sp1-win32/Vc7/include",
            "toolchain/msvc/7.1-sp1-win32/Vc7/lib",
        ),
    ),
    "msvc800": (
        (
            "toolchain/msvc/8.0-win32/VC/bin/cl.exe",
            "toolchain/msvc/8.0-win32/VC/include",
            "toolchain/msvc/8.0-win32/VC/lib",
        ),
    ),
    "msvc800sp1": (
        (
            "toolchain/msvc/8.0-sp1-win32/VC/bin/cl.exe",
            "toolchain/msvc/8.0-sp1-win32/VC/include",
            "toolchain/msvc/8.0-sp1-win32/VC/lib",
        ),
    ),
    "msvc900": (
        (
            "toolchain/msvc/9.0-win32/VC/bin/cl.exe",
            "toolchain/msvc/9.0-win32/VC/include",
            "toolchain/msvc/9.0-win32/VC/lib",
        ),
    ),
    "msvc1000": (
        (
            "toolchain/msvc/10.0-win32/VC/bin/cl.exe",
            "toolchain/msvc/10.0-win32/VC/include",
            "toolchain/msvc/10.0-win32/VC/lib",
        ),
    ),
    "msvc1000sp1": (
        (
            "toolchain/msvc/10.0-sp1-win32/VC/bin/cl.exe",
            "toolchain/msvc/10.0-sp1-win32/VC/include",
            "toolchain/msvc/10.0-sp1-win32/VC/lib",
        ),
    ),
    "msvc200": (
        (
            "toolchain/msvc/2.0-win32/bin/cl.exe",
            "toolchain/msvc/2.0-win32/include",
            "toolchain/msvc/2.0-win32/lib",
        ),
    ),
    "msvc410": (
        (
            "toolchain/msvc/4.1-win32/bin/CL.EXE",
            "toolchain/msvc/4.1-win32/include",
            "toolchain/msvc/4.1-win32/lib",
        ),
    ),
    "msvc500sp1": (
        (
            "toolchain/msvc/5.0-sp1-win32/bin/cl.exe",
            "toolchain/msvc/5.0-sp1-win32/include",
            "toolchain/msvc/5.0-sp1-win32/lib",
        ),
    ),
    "msvc500sp2": (
        (
            "toolchain/msvc/5.0-sp2-win32/bin/cl.exe",
            "toolchain/msvc/5.0-sp2-win32/include",
            "toolchain/msvc/5.0-sp2-win32/lib",
        ),
    ),
    "msvc500sp3": (
        (
            "toolchain/msvc/5.0-sp3-win32/bin/cl.exe",
            "toolchain/msvc/5.0-sp3-win32/include",
            "toolchain/msvc/5.0-sp3-win32/lib",
        ),
    ),
    "msvc600sp1": (
        ("toolchain/msvc/6.0-sp1-win32/VC98/bin/CL.EXE", "toolchain/msvc/6.0-sp1-win32/VC98/include", "toolchain/msvc/6.0-sp1-win32/VC98/lib"),
    ),
    "msvc600sp2": (
        ("toolchain/msvc/6.0-sp2-win32/VC98/bin/CL.EXE", "toolchain/msvc/6.0-sp2-win32/VC98/include", "toolchain/msvc/6.0-sp2-win32/VC98/lib"),
    ),
    "msvc600sp3": (
        ("toolchain/msvc/6.0-sp3-win32/Bin/CL.EXE", "toolchain/msvc/6.0-sp3-win32/Include", ""),
    ),
    "msvc600sp4": (
        (
            "toolchain/msvc/6.0-sp4-win32/VC98/bin/CL.EXE",
            "toolchain/msvc/6.0-sp4-win32/VC98/include",
            "toolchain/msvc/6.0-sp4-win32/VC98/lib",
        ),
    ),
    "msvc600sp5": (
        (
            "toolchain/msvc/6.0-sp5-win32/VC98/Bin/CL.EXE",
            "toolchain/msvc/6.0-sp5-win32/VC98/Include",
            "toolchain/msvc/6.0-sp5-win32/VC98/Lib",
        ),
    ),
    "msvc600sp6": (
        ("toolchain/msvc/6.0-sp6-win32/Bin/CL.EXE", "toolchain/msvc/6.0-sp6-win32/Include", ""),
    ),
    "msvc900sp1": (
        (
            "toolchain/msvc/9.0-sp1-win32/VC/bin/cl.exe",
            "toolchain/msvc/9.0-sp1-win32/VC/include",
            "toolchain/msvc/9.0-sp1-win32/VC/lib",
        ),
    ),
    "msvc1100": (
        (
            "toolchain/msvc/11.0-win32/VC/bin/cl.exe",
            "toolchain/msvc/11.0-win32/VC/include",
            "toolchain/msvc/11.0-win32/VC/lib",
        ),
    ),
    "msvc1.52": (
        (
            "toolchain/msvc/1.52-win16/BIN/CL.EXE",
            "toolchain/msvc/1.52-win16/INCLUDE",
            "toolchain/msvc/1.52-win16/LIB",
        ),
    ),
    "msvc15": (
        (
            "toolchain/msvc/1.5-win16/BIN/CL.EXE",
            "toolchain/msvc/1.5-win16/INCLUDE",
            "toolchain/msvc/1.5-win16/LIB",
        ),
    ),
    "msvc10": (
        (
            "toolchain/msvc/1.0-win16/BIN/CL.EXE",
            "toolchain/msvc/1.0-win16/INCLUDE",
            "toolchain/msvc/1.0-win16/LIB",
        ),
    ),
}


def resolve_msvc_toolchain(root: Path, profile: str) -> tuple[str, str, str] | None:
    """Resolve the best available layout for an MSVC *profile* in a project
    rooted at *root*: ``(command, includes, libs)`` as project-relative
    ``toolchain/...`` strings, or None when no layout exists.

    The command keeps the ``wine`` prefix; libs is empty for the
    compile-only mirrors.

    Project-provisioned layouts win over the rebrew install's own vendored
    tree: a project that linked only ``toolchain/msvc/6.0-sp6-win32`` from a
    master dir (``--link-tools-from``) must be handed the SP6 mirror even
    when the install happens to vendor the full 6.0 master — the command has
    to reference a layout the project itself provisioned.  The generated
    config then resolves the actual compiler through the same fallback if the
    linked dir is not yet populated.
    """
    layouts = _MSVC_LAYOUTS.get(profile, ())
    candidates = toolchain_link_candidates(profile)
    # Pass 1: project-provisioned layouts only — a compile-ready CL.EXE path
    # or a linked toolchain dir (symlink to a master, possibly empty).
    for i, (cl, inc, lib) in enumerate(layouts):
        if (root / cl).exists():
            return f"wine {cl}", inc, lib
        if i < len(candidates) and (root / "toolchain" / candidates[i]).exists():
            return f"wine {cl}", inc, lib
    # Pass 2: fall back to the rebrew install's own vendored tree.
    for cl, inc, lib in layouts:
        if find_install_tool(cl) is not None:
            return f"wine {cl}", inc, lib
    return None


def toolchain_link_candidates(profile: str) -> list[str]:
    """``toolchain/<family>/<version>-<arch>`` subpaths to try when linking
    *profile* from a master directory, best first (master then mirrors) —
    derived from the same layout table as :func:`resolve_msvc_toolchain` so
    the two cannot drift."""
    return ["/".join(cl.split("/")[1:3]) for cl, _, _ in _MSVC_LAYOUTS.get(profile, ())]


# Candidate encodings for C sources, most strict first.  MSVC6-era sources
# are often CP1252 (Western) or Shift-JIS (Japanese games) — the exact
# audience this tool targets.  UTF-8 first keeps the common case
# byte-identical; Shift-JIS second so Japanese sources round-trip (CP1252 is
# last because it decodes *every* byte sequence, so it must be the catch-all
# fallback rather than a first guess).
_SOURCE_ENCODINGS = ("utf-8", "shift_jis", "cp1252")


def detect_source_encoding(data: bytes) -> str:
    """Return the encoding *data* is in: UTF-8 when it decodes cleanly,
    otherwise Shift-JIS, else CP1252.

    Reading a legacy-encoded source as UTF-8 with ``errors="replace"`` and
    writing it back permanently replaces every non-ASCII byte with U+FFFD;
    detecting the real encoding on read lets write-backs round-trip
    byte-for-byte.  Ordering note: cp1252 is tried last as the fallback;
    shift_jis is stricter and catches Japanese sources first.
    """
    for enc in _SOURCE_ENCODINGS:
        try:
            data.decode(enc)
            return enc
        except UnicodeDecodeError:
            continue
    # cp1252 is the fallback even though a handful of bytes are undefined
    # (0x81, 0x8D, 0x8F, 0x90, 0x9D) — read_source_text decodes it with
    # errors="replace" so those rare bytes degrade to U+FFFD instead of
    # crashing the whole read.
    return "cp1252"


def read_source_text(filepath: Path) -> tuple[str, str]:
    """Read *filepath* tolerantly, returning ``(text, detected_encoding)``.

    Pass the returned encoding to :func:`atomic_write_text` when writing the
    file back so legacy-encoded sources are not corrupted by a UTF-8 write.
    Undecodable bytes (e.g. the undefined CP1252 holes 0x81/0x8D/0x8F/0x90/
    0x9D) decode as U+FFFD rather than raising.
    """
    data = filepath.read_bytes()
    encoding = detect_source_encoding(data)
    return data.decode(encoding, errors="replace"), encoding


def atomic_write_text(filepath: Path, text: str, encoding: str = "utf-8") -> None:
    """Write text to a file atomically to prevent corruption on crash.

    Strategy: write to a sibling .tmp file, then ``os.replace()`` (atomic
    on both POSIX and Windows/NTFS).  If *any* exception occurs —
    including KeyboardInterrupt — the temp file is cleaned up so we never
    leave partial writes at the target path.

    The temp name carries the writer's pid and thread id so two concurrent
    writers of the same target (e.g. ``rebrew verify`` and ``rebrew test``
    both promoting STATUS into ``rebrew-function.toml``) cannot interleave
    into one shared scratch file and publish a spliced result.  This makes
    each write self-contained; it does not serialise read-modify-write
    cycles, so a genuine last-writer-wins update is still possible.

    The ``contextlib.suppress(OSError)`` in the except path is safe because
    it only guards the cleanup unlink: if the temp file was already removed
    (race, OS cleanup) the unlink would raise, but we don't care — the
    original exception is re-raised regardless.
    """
    tmp_path = filepath.with_name(f"{filepath.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    # Ensure the target directory exists (metadata roots are often created
    # lazily on first write).
    filepath.parent.mkdir(parents=True, exist_ok=True)
    try:
        tmp_path.write_text(text, encoding=encoding)
        os.replace(tmp_path, filepath)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise


def preserve_corrupt(path: Path) -> Path | None:
    """Move an unparseable file aside to ``<name>.corrupt`` and return the new path.

    Callers that recover from a parse failure by rebuilding the document from
    scratch would otherwise overwrite the whole store (every function's STATUS,
    CFLAGS and notes) because of one bad byte.  Renaming first keeps the
    original recoverable.  Returns ``None`` if the rename failed (the file is
    gone or unwritable), in which case the caller has nothing to preserve.
    """
    backup = path.with_name(path.name + ".corrupt")
    try:
        os.replace(path, backup)
    except OSError:
        return None
    return backup


def load_toml_for_write(path: Path, description: str) -> TOMLDocument:
    """Parse *path* for a read-modify-write cycle, tolerating a corrupt store.

    Returns an empty document if the file is missing.  If it exists but cannot
    be parsed, the original is moved aside via :func:`preserve_corrupt` (so the
    caller's subsequent write does not silently discard every other entry) and
    an empty document is returned.

    *description* names the store in the warning (e.g. ``"metadata"``).
    """
    if not path.exists():
        return tomlkit.document()
    try:
        return tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — tomlkit raises various types
        backup = preserve_corrupt(path)
        logger.warning(
            "Failed to parse %s %s (%s); preserved as %s, starting fresh",
            description,
            path,
            exc,
            backup if backup is not None else "<not preserved>",
        )
        return tomlkit.document()


def qualified_key(module: str | None, va: int) -> str:
    """Return the canonical TOML key for *(module, va)*.

    Used by both ``metadata.py`` and ``data_metadata.py`` for consistent
    key encoding in ``rebrew-function.toml`` / ``rebrew-data.toml``.

    Examples::

        >>> qualified_key("SERVER", 0x01006364)
        'SERVER.0x01006364'
        >>> qualified_key(None, 0x01006364)
        '0x01006364'

    """
    va_hex = f"0x{va:08x}"
    if module:
        return f"{module}.{va_hex}"
    return va_hex


def parse_metadata_key(key: str) -> tuple[str, int] | None:
    """Parse a metadata TOML key into ``(module, va_int)``.

    Only accepts the qualified ``MODULE.0xVA`` form.  Returns ``None`` for
    unrecognised keys.

    Examples::

        >>> parse_metadata_key("SERVER.0x01006364")
        ('SERVER', 16802660)
        >>> parse_metadata_key("not_a_key") is None
        True

    """
    if ".0x" in key:
        dot = key.index(".0x")
        module = key[:dot]
        hex_part = key[dot + 1 :]  # includes leading 0x
        try:
            return module, int(hex_part, 16)
        except ValueError:
            return None
    return None


def parse_metadata_doc(doc: TOMLDocument) -> dict[tuple[str, int], dict[str, Any]]:
    """Convert a parsed metadata TOML document into ``{(module, va): fields}``.

    Entries whose key is not a qualified ``MODULE.0xVA`` form, or whose value
    is not a table, are skipped.  Shared by ``metadata.py`` and
    ``data_metadata.py``.
    """
    result: dict[tuple[str, int], dict[str, Any]] = {}
    for key, value in doc.items():
        parsed = parse_metadata_key(key)
        if parsed is None or not isinstance(value, dict):
            continue
        result[parsed] = dict(value)
    return result


def build_metadata_doc(
    data: dict[tuple[str, int], dict[str, Any]],
    canonical_order: Sequence[str],
) -> TOMLDocument:
    """Render ``{(module, va): fields}`` into a TOML document.

    Entries are sorted by ``(module, va)`` for stable diffs, and fields are
    emitted in *canonical_order* first, then any remaining fields in insertion
    order.  Empty entries are dropped.
    """
    doc = tomlkit.document()
    for module, va_int in sorted(data):
        entry = data[(module, va_int)]
        if not entry:
            continue
        tbl = tomlkit.table()
        for field in canonical_order:
            if field in entry:
                tbl[field] = entry[field]
        for field, val in entry.items():
            if field not in canonical_order:
                tbl[field] = val
        doc[qualified_key(module, va_int)] = tbl
    return doc


def safe_shlex_split(command: str) -> list[str]:
    """Split a shell command string, falling back to str.split() on parse errors.

    Handles unbalanced quotes in compiler commands gracefully.
    """
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def watch_files(
    paths: list[Path],
    retest: Callable[[], None],
    interval: float = 1.0,
    path_provider: Callable[[], list[Path]] | None = None,
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
    loop silently stopping to cover them (idempotency-review F8).
    """
    from rich.console import Console

    _console = Console(stderr=True)

    def _current_paths() -> list[Path]:
        return path_provider() if path_provider is not None else paths

    def _mtimes() -> dict[Path, int]:
        out: dict[Path, int] = {}
        for p in _current_paths():
            try:
                out[p] = p.stat().st_mtime_ns
            except OSError:
                continue
        return out

    last = _mtimes()
    _console.print(
        f"[dim]Watching {len(last)} file(s) — re-run on every save (Ctrl+C to stop)...[/dim]"
    )
    try:
        while True:
            time.sleep(interval)
            current = _mtimes()
            if current == last:
                continue
            last = current
            try:
                retest()
            except BaseException as exc:  # noqa: BLE001 — keep watching after a failed run
                if isinstance(exc, KeyboardInterrupt):
                    raise
                _console.print(
                    f"[dim]Run failed ({exc.__class__.__name__}) — waiting for a fix...[/dim]"
                )
    except KeyboardInterrupt:
        _console.print("[dim]Watch stopped.[/dim]")


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
    """
    out: list[str] = []
    in_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "*/":
            # Closes an open comment block (or a harmless orphan).
            in_block = False
            continue
        if stripped.startswith("* ") and not in_block:
            # Orphaned comment-continuation lines (malformed /* */ nesting).
            # Inside a block, a `* ` prefix is just comment content — the line
            # must still go through the scanner so a trailing `*/` (possibly
            # followed by code) is honoured instead of leaving the block open.
            continue
        buf: list[str] = []
        in_string = False
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
                if ch == '"':
                    in_string = False
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
            if ch == '"':
                in_string = True
            i += 1
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


def writable_temp_dir(prefix: str) -> Path:
    """Create a writable temp dir on a real-disk, container-visible location.

    Compile sandboxes must live on a real disk: DOSBox breaks on tmpfs
    mounts, and the docker runner mounts the workdir at /work, so a
    sandbox under the system temp dir (often tmpfs, and invisible to
    docker in sandboxed environments) silently breaks the compile.  The
    user's home is preferred when writable; when it is read-only
    (sandboxed homes / CI) fall back to the rebrew workspace ``.cache``
    (a real disk, visible to docker) and then the system temp dir.

    Raises :class:`OSError` when no candidate is writable."""
    import tempfile

    workspace = Path(__file__).resolve().parents[2] / ".cache"
    candidates = [Path.home(), workspace]
    with contextlib.suppress(Exception):
        candidates.append(Path(tempfile.gettempdir()))
    for base in candidates:
        try:
            base.mkdir(parents=True, exist_ok=True)
            return Path(tempfile.mkdtemp(prefix=prefix, dir=base))
        except OSError:
            continue
    raise OSError(f"no writable directory for temp dir {prefix!r}")
