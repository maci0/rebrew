"""Shared utilities for rebrew."""

import contextlib
import copy
import logging
import os
import shlex
import threading
import time
import tomllib
from collections import OrderedDict
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import tomlkit
from tomlkit import TOMLDocument
from tomlkit.exceptions import InternalParserError, ParseError

logger = logging.getLogger(__name__)

# The rebrew package's own vendored toolchains (toolchain/msvc/5.0-win32, toolchain/watcom/2.0-win32,
# ...).  Projects resolve compiler paths project-relative first, then fall
# back here so a freshly-inited project works without a local tools/ symlink.
_REPO_ROOT = Path(__file__).resolve().parents[2]

# Process-lifetime source text memo keyed by (resolved path, mtime_ns, size).
# verify/test/catalog re-read the same tree multiple times per run; a bounded
# LRU collapses those duplicate syscalls without pinning unbounded content.
# Guarded: verify -j N reads the same sources from worker threads.
_SOURCE_TEXT_MEMO: OrderedDict[tuple[str, int, int], tuple[str, str]] = OrderedDict()
_SOURCE_TEXT_MEMO_MAX = 512
_SOURCE_TEXT_MEMO_LOCK = threading.Lock()


def container_runtime() -> str:
    """The container runtime used for docker-shipped tools.

    Configurable via ``REBREW_CONTAINER_RUNTIME`` so podman (crun-backed,
    daemonless) or nerdctl can be used instead of dockerd — same knob the Go
    port honors.  Defaults to ``docker``.  Empty / whitespace-only values
    are treated as unset (``os.environ.get`` alone would return ``""`` and
    break every ``docker``/``podman`` invocation).
    """
    return os.environ.get("REBREW_CONTAINER_RUNTIME", "docker").strip() or "docker"


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


def md5_file(path: Path) -> str:
    """MD5 hex digest of a file, matching BinSync's ``binary_hash``.

    IDA (``retrieve_input_file_md5().hex()``), Ghidra (``executableMD5``),
    Binary Ninja (``md5(bv.file.raw)``), and declib's file loader all hash the
    raw binary bytes, so this reproduces the value a BinSync state dir stores.
    """
    import hashlib

    digest = hashlib.md5()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


#: Candidate MSVC toolchain layouts per profile, best first: the full master
#: (Bin+Include+Lib) then the vendored compile-only mirrors (newer codegen
#: first — docs/TOOLCHAIN.md notes SP3 codegen differs from SP6).  The mirror
#: dirs carry version suffixes (msvc-6.0-sp3-win32/6.6/7.0) while the master keeps the
#: classic names (msvc-6.0-win32/VC98, msvc-7.0-win32), so a machine with only the mirrors
#: must not be handed a broken master path.
_MSVC_LAYOUTS: dict[str, tuple[tuple[str, str, str], ...]] = {
    "msvc-6.0": (
        (
            "toolchain/msvc/6.0-win32/source/VC98/Bin/CL.EXE",
            "toolchain/msvc/6.0-win32/source/VC98/Include",
            "toolchain/msvc/6.0-win32/source/VC98/Lib",
        ),
        (
            "toolchain/msvc/6.0-sp6-win32/source/Bin/CL.EXE",
            "toolchain/msvc/6.0-sp6-win32/source/Include",
            "",
        ),
        (
            "toolchain/msvc/6.0-sp3-win32/source/Bin/CL.EXE",
            "toolchain/msvc/6.0-sp3-win32/source/Include",
            "",
        ),
    ),
    "msvc-7.0": (
        (
            "toolchain/msvc/7.0-win32/source/Bin/cl.exe",
            "toolchain/msvc/7.0-win32/source/Include",
            "toolchain/msvc/7.0-win32/source/Lib",
        ),
        (
            "toolchain/msvc/7.0-win32/source/Bin/cl.exe",
            "toolchain/msvc/7.0-win32/source/Include",
            "",
        ),
    ),
    "msvc-7.0-rtm": (
        (
            "toolchain/msvc/7.0-rtm-win32/source/Vc7/bin/cl.exe",
            "toolchain/msvc/7.0-rtm-win32/source/Vc7/include",
            "toolchain/msvc/7.0-rtm-win32/source/Vc7/lib",
        ),
    ),
    "msvc-7.0-sp1": (
        (
            "toolchain/msvc/7.0-sp1-win32/source/Vc7/bin/cl.exe",
            "toolchain/msvc/7.0-sp1-win32/source/Vc7/include",
            "toolchain/msvc/7.0-sp1-win32/source/Vc7/lib",
        ),
    ),
    "msvc-7.1": (
        (
            "toolchain/msvc/7.1-win32/source/Vc7/bin/cl.exe",
            "toolchain/msvc/7.1-win32/source/Vc7/include",
            "toolchain/msvc/7.1-win32/source/Vc7/lib",
        ),
    ),
    "msvc-7.1-sp1": (
        (
            "toolchain/msvc/7.1-sp1-win32/source/Vc7/bin/cl.exe",
            "toolchain/msvc/7.1-sp1-win32/source/Vc7/include",
            "toolchain/msvc/7.1-sp1-win32/source/Vc7/lib",
        ),
    ),
    "msvc-8.0": (
        (
            "toolchain/msvc/8.0-win32/source/VC/bin/cl.exe",
            "toolchain/msvc/8.0-win32/source/VC/include",
            "toolchain/msvc/8.0-win32/source/VC/lib",
        ),
    ),
    "msvc-8.0-sp1": (
        (
            "toolchain/msvc/8.0-sp1-win32/source/VC/bin/cl.exe",
            "toolchain/msvc/8.0-sp1-win32/source/VC/include",
            "toolchain/msvc/8.0-sp1-win32/source/VC/lib",
        ),
    ),
    "msvc-9.0": (
        (
            "toolchain/msvc/9.0-win32/source/VC/bin/cl.exe",
            "toolchain/msvc/9.0-win32/source/VC/include",
            "toolchain/msvc/9.0-win32/source/VC/lib",
        ),
    ),
    "msvc-10.0": (
        (
            "toolchain/msvc/10.0-win32/source/VC/bin/cl.exe",
            "toolchain/msvc/10.0-win32/source/VC/include",
            "toolchain/msvc/10.0-win32/source/VC/lib",
        ),
    ),
    "msvc-10.0-sp1": (
        (
            "toolchain/msvc/10.0-sp1-win32/source/VC/bin/cl.exe",
            "toolchain/msvc/10.0-sp1-win32/source/VC/include",
            "toolchain/msvc/10.0-sp1-win32/source/VC/lib",
        ),
    ),
    "msvc-2.0": (
        (
            "toolchain/msvc/2.0-win32/source/bin/cl.exe",
            "toolchain/msvc/2.0-win32/source/include",
            "toolchain/msvc/2.0-win32/source/lib",
        ),
    ),
    "msvc-4.1": (
        (
            "toolchain/msvc/4.1-win32/source/bin/CL.EXE",
            "toolchain/msvc/4.1-win32/source/include",
            "toolchain/msvc/4.1-win32/source/lib",
        ),
    ),
    "msvc-5.0-sp1": (
        (
            "toolchain/msvc/5.0-sp1-win32/source/bin/cl.exe",
            "toolchain/msvc/5.0-sp1-win32/source/include",
            "toolchain/msvc/5.0-sp1-win32/source/lib",
        ),
    ),
    "msvc-5.0-sp2": (
        (
            "toolchain/msvc/5.0-sp2-win32/source/bin/cl.exe",
            "toolchain/msvc/5.0-sp2-win32/source/include",
            "toolchain/msvc/5.0-sp2-win32/source/lib",
        ),
    ),
    "msvc-5.0-sp3": (
        (
            "toolchain/msvc/5.0-sp3-win32/source/bin/cl.exe",
            "toolchain/msvc/5.0-sp3-win32/source/include",
            "toolchain/msvc/5.0-sp3-win32/source/lib",
        ),
    ),
    "msvc-6.0-sp1": (
        (
            "toolchain/msvc/6.0-sp1-win32/source/VC98/bin/CL.EXE",
            "toolchain/msvc/6.0-sp1-win32/source/VC98/include",
            "toolchain/msvc/6.0-sp1-win32/source/VC98/lib",
        ),
    ),
    "msvc-6.0-sp2": (
        (
            "toolchain/msvc/6.0-sp2-win32/source/VC98/bin/CL.EXE",
            "toolchain/msvc/6.0-sp2-win32/source/VC98/include",
            "toolchain/msvc/6.0-sp2-win32/source/VC98/lib",
        ),
    ),
    "msvc-6.0-sp3": (
        (
            "toolchain/msvc/6.0-sp3-win32/source/Bin/CL.EXE",
            "toolchain/msvc/6.0-sp3-win32/source/Include",
            "",
        ),
    ),
    "msvc-6.0-sp4": (
        (
            "toolchain/msvc/6.0-sp4-win32/source/VC98/bin/CL.EXE",
            "toolchain/msvc/6.0-sp4-win32/source/VC98/include",
            "toolchain/msvc/6.0-sp4-win32/source/VC98/lib",
        ),
    ),
    "msvc-6.0-sp5": (
        (
            "toolchain/msvc/6.0-sp5-win32/source/VC98/Bin/CL.EXE",
            "toolchain/msvc/6.0-sp5-win32/source/VC98/Include",
            "toolchain/msvc/6.0-sp5-win32/source/VC98/Lib",
        ),
    ),
    "msvc-6.0-sp5-pp": (
        (
            "toolchain/msvc/6.0-sp5-pp-win32/source/VC98/Bin/CL.EXE",
            "toolchain/msvc/6.0-sp5-pp-win32/source/VC98/Include",
            "toolchain/msvc/6.0-sp5-pp-win32/source/VC98/Lib",
        ),
    ),
    "msvc-6.0-sp6": (
        (
            "toolchain/msvc/6.0-sp6-win32/source/Bin/CL.EXE",
            "toolchain/msvc/6.0-sp6-win32/source/Include",
            "",
        ),
    ),
    "msvc-9.0-sp1": (
        (
            "toolchain/msvc/9.0-sp1-win32/source/VC/bin/cl.exe",
            "toolchain/msvc/9.0-sp1-win32/source/VC/include",
            "toolchain/msvc/9.0-sp1-win32/source/VC/lib",
        ),
    ),
    "msvc-11.0": (
        (
            "toolchain/msvc/11.0-win32/source/VC/bin/cl.exe",
            "toolchain/msvc/11.0-win32/source/VC/include",
            "toolchain/msvc/11.0-win32/source/VC/lib",
        ),
    ),
    "msvc-1.52": (
        (
            "toolchain/msvc/1.52-win16/source/BIN/CL.EXE",
            "toolchain/msvc/1.52-win16/source/INCLUDE",
            "toolchain/msvc/1.52-win16/source/LIB",
        ),
    ),
    "msvc-1.5": (
        (
            "toolchain/msvc/1.5-win16/source/BIN/CL.EXE",
            "toolchain/msvc/1.5-win16/source/INCLUDE",
            "toolchain/msvc/1.5-win16/source/LIB",
        ),
    ),
    "msvc-1.0": (
        (
            "toolchain/msvc/1.0-win16/source/BIN/CL.EXE",
            "toolchain/msvc/1.0-win16/source/INCLUDE",
            "toolchain/msvc/1.0-win16/source/LIB",
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

    Bounded path+mtime memo: verify/test/catalog often re-scan the same
    tree several times per run (prepare_entries, build_name_to_va,
    scan_globals).  A content-digest parse memo still re-reads every file;
    this layer skips the syscall+decode when the inode metadata is unchanged.
    """
    resolved = filepath.resolve()
    try:
        st = resolved.stat()
    except OSError:
        # Fall through to a direct read so the caller's OSError path matches
        # the pre-cache behaviour (missing file, permission, etc.).
        data = filepath.read_bytes()
        encoding = detect_source_encoding(data)
        return data.decode(encoding, errors="replace"), encoding
    memo_key = (str(resolved), st.st_mtime_ns, st.st_size)
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
        if memo_key not in _SOURCE_TEXT_MEMO and len(_SOURCE_TEXT_MEMO) >= _SOURCE_TEXT_MEMO_MAX:
            _SOURCE_TEXT_MEMO.popitem(last=False)
        _SOURCE_TEXT_MEMO[memo_key] = (text, encoding)
    return text, encoding


def atomic_write_text(filepath: Path, text: str, encoding: str = "utf-8") -> None:
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
        # newline="" keeps the caller's line endings byte-exact.  Path.write_text
        # defaults to newline=None, which on Windows translates ``\n`` to
        # ``\r\n`` and would CRLF-corrupt every LF source/metadata rewrite.
        tmp_path.write_text(text, encoding=encoding, newline="")
        os.replace(tmp_path, filepath)
        # Drop any stale path+mtime entries so a same-ns rewrite cannot
        # serve pre-write content to a later reader in this process.
        try:
            resolved = str(filepath.resolve())
        except OSError:
            resolved = ""
        if resolved:
            with _SOURCE_TEXT_MEMO_LOCK:
                stale = [k for k in _SOURCE_TEXT_MEMO if k[0] == resolved]
                for k in stale:
                    _SOURCE_TEXT_MEMO.pop(k, None)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise


def atomic_write_bytes(filepath: Path, data: bytes) -> None:
    """Byte counterpart of :func:`atomic_write_text`.

    Writes to a sibling ``.<pid>.<tid>.tmp`` then ``os.replace()``s, so a
    crash or disk-full mid-write never leaves a truncated binary at the
    target path (e.g. a postlinked or reassembled PE).  The temp file is
    cleaned up on any failure; the original exception is always re-raised.
    """
    tmp_path = filepath.with_name(f"{filepath.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    filepath.parent.mkdir(parents=True, exist_ok=True)
    try:
        tmp_path.write_bytes(data)
        os.replace(tmp_path, filepath)
    except PermissionError as exc:
        # A read-only destination dir (e.g. a versioned originals/ tree)
        # rejects even the sibling temp file; the final replace would fail
        # too, so say where to put the output instead of leaking errno 13.
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise PermissionError(
            f"{exc}: cannot write next to {filepath} (directory is read-only?) — "
            "pass an explicit output path"
        ) from exc
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise


def atomic_write_locked(filepath: Path | str, text: str, encoding: str = "utf-8") -> None:
    """Write *text* atomically, leaving the file read-only (mode 0444).

    The metadata write-lock discipline for tool-owned files
    (``rebrew-functions.toml``, ``rebrew-data.toml``, the binsync
    ``functions/*.toml`` / ``global_vars.toml`` / ``structs/*.toml``
    exports): **chmod writable before touching, write, chmod read-only
    after** (metadata-review F1).  Direct edits by hand fail with
    Permission denied; the only sanctioned path is the CLI, which chmods
    writable, updates, and re-locks.

    The chmod-before is also required on Windows, where ``os.replace`` over
    a read-only target fails — un-readonlying first keeps the atomic
    replace working.

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
        with contextlib.suppress(OSError):
            os.chmod(filepath, 0o444)
        raise
    with contextlib.suppress(OSError):
        os.chmod(filepath, 0o444)  # chmod after touching — direct edits now fail


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
        for _ in range(10_000):
            candidate = path.with_name(f"{path.name}.{suffix}.corrupt")
            if not candidate.exists():
                backup = candidate
                break
            suffix += 1
        else:
            raise OSError(
                f"cannot preserve corrupt store {path}: no free .corrupt slot after 10000 attempts"
            )
    os.replace(path, backup)
    return backup


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
        return tomlkit.parse(path.read_text(encoding="utf-8"))
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


#: Per-file thread locks for :func:`metadata_write_lock` (one lock per
#: metadata filename so the function and data stores don't contend).
#: Reentrant: a caller may hold the lock across a compound operation whose
#: helpers take it again (the GA batch splices a stub and promotes its STATUS
#: through ``update_source_status`` inside the same critical section).
_METADATA_WRITE_LOCKS: dict[str, threading.RLock] = {}

#: Per-thread reentrancy depth per metadata filename, so a nested acquisition
#: skips the ``flock`` (a second fd would deadlock against the first).
_METADATA_WRITE_DEPTH = threading.local()


@contextlib.contextmanager
def metadata_write_lock(directory: Path, filename: str) -> Iterator[None]:
    """Thread + cross-process lock around a metadata read-modify-write.

    Shared by ``metadata.py`` (``rebrew-functions.toml``) and
    ``data_metadata.py`` (``rebrew-data.toml``).  The thread lock serializes
    in-process writers (``rebrew verify --jobs``, GA batch promotion); an
    advisory ``flock`` on a ``.lock`` sidecar serializes *concurrent
    processes* (e.g. ``rebrew verify --watch`` in one terminal while
    ``rebrew test`` promotes in another — without it, interleaved
    read-modify-writes silently drop one process's STATUS promotion).
    Falls back to the thread lock alone on platforms without ``fcntl``.

    Reentrant within one thread: a nested acquisition on the same filename
    yields without re-``flock``ing (the flock is held until the outermost
    exit), so a compound critical section can call helpers that lock again.
    """
    try:
        import fcntl
    except ImportError:  # non-POSIX (no advisory file locks)
        fcntl = None  # type: ignore[assignment]

    path = (directory / filename).resolve()
    # Reject directory-traversal filenames (e.g. "../../etc/passwd") — the
    # lock file is derived from this path and would otherwise escape the
    # project root.
    if Path(filename).name != filename or "/" in filename or "\\" in filename:
        raise ValueError(f"invalid metadata filename: {filename!r}")
    # Create the target directory before opening the ``.lock`` sidecar: the
    # first-ever write into a fresh metadata root would otherwise crash with
    # FileNotFoundError inside the lock acquisition (the data write itself
    # only runs later, inside atomic_write_text's own mkdir).  exist_ok
    # keeps concurrent creators safe.
    path.parent.mkdir(parents=True, exist_ok=True)
    # A single atomic setdefault: the get-then-setdefault race published a
    # second Lock that no other thread saw, so two writers could hold
    # different locks for the same file.
    lock = _METADATA_WRITE_LOCKS.setdefault(filename, threading.RLock())
    depth: dict[str, int] | None = getattr(_METADATA_WRITE_DEPTH, "depth", None)
    if depth is None:
        depth = {}
        _METADATA_WRITE_DEPTH.depth = depth
    with lock:
        if depth.get(filename, 0):
            # Reentrant: this thread already holds the lock and the flock.
            # Re-opening the sidecar and flocking a second fd would block
            # against the first, so only track the depth here.
            depth[filename] += 1
            try:
                yield
            finally:
                depth[filename] -= 1
            return
        depth[filename] = 1
        try:
            if fcntl is None:
                yield
                return
            lock_path = path.with_suffix(path.suffix + ".lock")
            with lock_path.open("w", encoding="utf-8") as lock_fh:
                fcntl.flock(lock_fh, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_fh, fcntl.LOCK_UN)
        finally:
            depth.pop(filename, None)


#: Serializes in-memory metadata-doc cache mutations (``rebrew-functions.toml``
#: / ``rebrew-data.toml``).  ``rebrew verify -j N`` fills the cache from
#: workers while ``rebrew test`` / match / GA writers pop after STATUS
#: promotion — unguarded clear/pop vs fill races the shared dict.
_METADATA_DOC_CACHE_LOCK = threading.Lock()
#: Cap entries so a long-lived process that walks many project roots (or a
#: large pytest session with unique tmp_path TOMLs) cannot retain every
#: parsed table until exit.  Eviction is FIFO on insertion order.
_METADATA_DOC_CACHE_MAX = 64


def pop_metadata_doc_cache(
    cache: dict[Path, tuple[int, dict[tuple[str, int], dict[str, Any]]]],
    path: Path,
) -> None:
    """Drop one entry from a metadata-doc cache under the shared lock."""
    with _METADATA_DOC_CACHE_LOCK:
        cache.pop(path, None)


def clear_metadata_doc_cache(
    cache: dict[Path, tuple[int, dict[tuple[str, int], dict[str, Any]]]],
) -> None:
    """Clear a metadata-doc cache under the shared lock."""
    with _METADATA_DOC_CACHE_LOCK:
        cache.clear()


def load_metadata_doc(
    path: Path,
    cache: dict[Path, tuple[int, dict[tuple[str, int], dict[str, Any]]]],
    description: str,
    *,
    deepcopy: bool = True,
) -> dict[tuple[str, int], dict[str, Any]]:
    """Parse a qualified-key metadata TOML (``rebrew-functions.toml`` /
    ``rebrew-data.toml``) into ``{(module, va): fields}``.

    Shared by ``metadata.load_metadata`` and ``data_metadata.load_data_metadata``,
    which previously each hand-rolled the load→parse→mtime-cache pattern
    (with an inconsistent parser choice: tomlkit vs tomllib).  Reads use
    tomllib (strict, ~10x faster than tomlkit); round-trip preservation is
    only needed for WRITES, which still use tomlkit.

    *path* is resolved for stable cache keys.  *cache* is the caller's
    mtime-keyed in-memory cache (invalidated by write helpers).  Returns an
    empty dict when the file is missing or unparseable.

    When *deepcopy* is True (default), each caller receives an isolated
    copy so mutating overlays cannot corrupt the cache.  Read-only
    overlays (annotation finalize, skip checks) pass ``deepcopy=False``
    to avoid cloning the whole table once per source file.
    """
    path = path.resolve()
    if not path.exists():
        pop_metadata_doc_cache(cache, path)
        return {}

    try:
        current_mtime = path.stat().st_mtime_ns
    except OSError:
        current_mtime = 0
    with _METADATA_DOC_CACHE_LOCK:
        cached = cache.get(path)
        if cached is not None and cached[0] == current_mtime:
            # Deep copy: callers mutate the entries they get (merge overlays,
            # status promotion), and an aliased dict would corrupt the cache.
            return copy.deepcopy(cached[1]) if deepcopy else cached[1]

    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # parser raises various types
        logger.warning("Failed to parse %s %s: %s", description, path, exc)
        return {}

    result = parse_metadata_doc(doc)
    with _METADATA_DOC_CACHE_LOCK:
        # Re-check: a writer may have invalidated (or another reader filled)
        # while we parsed — prefer a fresher entry if one landed.
        cached = cache.get(path)
        if cached is not None and cached[0] == current_mtime:
            return copy.deepcopy(cached[1]) if deepcopy else cached[1]
        if len(cache) >= _METADATA_DOC_CACHE_MAX and path not in cache:
            oldest = next(iter(cache))
            cache.pop(oldest, None)
        cache[path] = (current_mtime, result)
    # Deep copy for the same reason as the cache-hit path above.
    return copy.deepcopy(result) if deepcopy else result


def qualified_key(module: str | None, va: int) -> str:
    """Return the canonical TOML key for *(module, va)*.

    Used by both ``metadata.py`` and ``data_metadata.py`` for consistent
    key encoding in ``rebrew-functions.toml`` / ``rebrew-data.toml``.

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


def build_metadata_key_index(doc: dict[str, Any]) -> dict[tuple[str, int], str]:
    """Map ``(module, va)`` → existing key spelling for *doc*.

    Built once per batch write so :func:`resolve_metadata_key` is O(1) per
    update instead of O(n) (intake / verify STATUS sync grow as O(n²) without
    this when every new entry misses the canonical spelling and rescans).
    Prefers the canonical spelling when both forms are present.
    """
    index: dict[tuple[str, int], str] = {}
    for existing in doc:
        parsed = parse_metadata_key(str(existing))
        if parsed is None:
            continue
        key = str(existing)
        if parsed not in index or key == qualified_key(*parsed):
            index[parsed] = key
    return index


def resolve_metadata_key(
    doc: dict[str, Any],
    module: str,
    va: int,
    *,
    index: dict[tuple[str, int], str] | None = None,
) -> str:
    """Return the key naming *(module, va)* in the raw *doc*.

    :func:`parse_metadata_key` reads the VA with ``int(hex, 16)``, so a store
    may spell one entry ``SERVER.0x24000`` and another ``SERVER.0x00024000``
    while the loader sees a single ``("SERVER", 0x24000)``.  A writer that
    only tests :func:`qualified_key` then appends a second table instead of
    updating the first, and the fields split across the two.

    Prefers the canonical spelling, falls back to whatever spelling the store
    already uses, and returns the canonical key when the entry is absent so
    callers can create it.  Shared by ``metadata.py`` and ``data_metadata.py``.

    Pass *index* (from :func:`build_metadata_key_index`) on batch writers so
    each resolve stays O(1); without it, a missing canonical key falls back
    to a linear scan (fine for single-entry writers).
    """
    canonical = qualified_key(module, va)
    if canonical in doc:
        return canonical
    want = (module, va)
    if index is not None:
        existing = index.get(want)
        if existing is not None and existing in doc:
            return existing
        return canonical
    # Common alternate: unpadded hex (SERVER.0x24000 vs SERVER.0x00024000).
    if module:
        alt = f"{module}.0x{va:x}"
        if alt in doc:
            return alt
    for existing in doc:
        if parse_metadata_key(str(existing)) == want:
            return str(existing)
    return canonical


def parse_metadata_doc(doc: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
    """Convert a parsed metadata TOML document into ``{(module, va): fields}``.

    Accepts either a tomlkit ``TOMLDocument`` (writes) or a plain ``dict``
    from ``tomllib`` (fast reads).  Entries whose key is not a qualified
    ``MODULE.0xVA`` form, or whose value is not a table, are skipped.  Shared
    by ``metadata.py`` and ``data_metadata.py``.

    Two keys that parse to the same ``(module, va)``, e.g. ``0x24000`` and
    ``0x00024000``, are merged field by field (the later key wins a contested
    field) and logged.  Whole-table replacement would silently drop the
    earlier entry's fields, which is how a duplicated key turned a populated
    entry into a status-only stub.
    """
    result: dict[tuple[str, int], dict[str, Any]] = {}
    first_key: dict[tuple[str, int], str] = {}
    for key, value in doc.items():
        parsed = parse_metadata_key(key)
        if parsed is None or not isinstance(value, dict):
            continue
        previous = result.get(parsed)
        if previous is not None:
            logger.warning(
                "Duplicate metadata keys %r and %r both resolve to %s 0x%x; "
                "merging their fields (later key wins). Collapse them to the "
                "canonical key %r to stop the split.",
                first_key[parsed],
                key,
                parsed[0],
                parsed[1],
                qualified_key(parsed[0], parsed[1]),
            )
            previous.update(copy.deepcopy(value))
            continue
        result[parsed] = copy.deepcopy(value)
        first_key[parsed] = key
    return result


def canonical_va_key(va: Any) -> Any:
    """Normalize a bare-VA key to its canonical form.

    Hex strings (``0x1000`` vs ``0x00001000``) map to the same int so key
    spelling drift can't silently break lookups.  Non-hex values pass
    through unchanged (still unique).  The single parser for bare-VA keys
    in JSON files (verify cache, verify reports); TOML ``MODULE.0xVA`` keys
    go through :func:`parse_metadata_key` instead.
    """
    if isinstance(va, int):
        return va
    if isinstance(va, str):
        s = va.strip()
        if s[:2].lower() == "0x":
            try:
                return int(s, 16)
            except ValueError:
                return s
    return str(va)


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
            except BaseException as exc:  # keep watching after a failed run
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
    in_string_global = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "*/":
            # Closes an open comment block (or a harmless orphan).
            # Also reset global string state — we are outside any string on a new line
            # after a block comment close; the per-line scanner handles the rest.
            in_block = False
            in_string_global = False
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
                if ch in ('"', "'"):
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
            if ch in ('"', "'"):
                in_string = True
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


def writable_temp_dir(prefix: str) -> Path:
    """Create a writable temp dir on a real-disk, container-visible location.

    Compile sandboxes must live on a real disk: DOSBox breaks on tmpfs
    mounts, and the docker runner mounts the workdir at /work, so a
    sandbox under the system temp dir (often tmpfs, and invisible to
    docker in sandboxed environments) silently breaks the compile.  The
    user's cache dir is preferred when writable; when it is read-only
    (sandboxed homes / CI) fall back to the rebrew workspace ``.cache``
    (a real disk, visible to docker) and then the system temp dir.

    Cache sandboxes live under ``$XDG_CACHE_HOME/rebrew/tmp`` when that
    variable is set, otherwise ``~/.cache/rebrew/tmp``, so that a straggler
    left behind by a hard-killed run stays out of ``~`` and is trivially
    sweepable.

    Raises :class:`OSError` when no candidate is writable."""
    import tempfile

    workspace = Path(__file__).resolve().parents[2] / ".cache"
    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    cache_root = Path(xdg) if xdg else Path.home() / ".cache"
    home_tmp = cache_root / "rebrew" / "tmp"
    candidates = [home_tmp, workspace]
    with contextlib.suppress(Exception):
        candidates.append(Path(tempfile.gettempdir()))
    for base in candidates:
        try:
            base.mkdir(parents=True, exist_ok=True)
            return Path(tempfile.mkdtemp(prefix=prefix, dir=base))
        except OSError:
            continue
    raise OSError(f"no writable directory for temp dir {prefix!r}")


def remove_temp_dir(path: Path, retries: int = 5, delay: float = 0.2) -> None:
    """Remove a temp dir created by :func:`writable_temp_dir`.

    A container that has not released its mount yet makes the top-level
    dir non-removable ("Device or resource busy") even after its contents
    are gone; the short retry absorbs the unmount race so sandboxes do not
    accumulate empty shells in their parent.  Raises :class:`OSError` when
    the dir is still busy after *retries*.
    """
    import shutil
    import time

    for attempt in range(retries):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            if attempt == retries - 1:
                raise
            time.sleep(delay)


def config_path(rel: str | Path) -> Path:
    """Build a :class:`~pathlib.Path` from a config / YAML / CLI path string.

    Project files and splat YAML may use Windows separators.  On POSIX,
    ``Path("src\\\\foo.c")`` is a single name component containing a
    literal backslash, so ``src\\\\foo.c`` never resolves to ``src/foo.c``.
    Normalize separators before constructing the path.  Absolute Windows
    drive paths (``C:/…``) stay non-absolute on POSIX — they cannot be
    used as host paths on Linux and are left for the caller to reject.
    """
    return Path(os.fspath(rel).replace("\\", "/"))


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


def parse_int_literal(text: str, *, base: int = 10) -> int:
    """Parse a C-style integer literal.

    A ``0x``/``0X`` prefix selects base 16; anything else uses *base* (decimal
    by default).  Raises ``ValueError`` on a malformed literal, so callers that
    want a fallback can catch it, and callers that must fail loud (the CLI's
    ``parse_va``) let it propagate.

    This is the one literal parser: the ad-hoc ``int(s, 16) if s.startswith(
    "0x") else int(s)`` copies in ``struct_recover``, ``name_decomp``,
    ``stack_cmp``, ``switch``, and the Ghidra backends all resolve here.
    """
    stripped = text.strip()
    if stripped.lower().startswith("0x"):
        return int(stripped, 16)
    return int(stripped, base)
