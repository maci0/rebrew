"""metadata_doc.py — qualified-key algebra and document access for the metadata TOMLs.

``rebrew-functions.toml`` and ``rebrew-data.toml`` are keyed by *qualified
module+VA string* (``SERVER.0x01006364``).  The key spelling, the parse to
``{(module, va): fields}``, the stat-fingerprinted read cache and the
write lock around a read-modify-write are one concern shared by
:mod:`rebrew.metadata` (function store) and :mod:`rebrew.data_metadata` (data
store); they live here so neither store hands-rolls a second copy.

Leaf module: it imports :mod:`rebrew.utils` and nothing else from rebrew, so
both stores and their readers can depend on it without a cycle.
"""

import contextlib
import copy
import logging
import threading
import unicodedata
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import tomlkit
from tomlkit import TOMLDocument

from rebrew.utils import file_lock, load_tomllib

logger = logging.getLogger(__name__)

#: Per-file thread locks for :func:`metadata_write_lock` (one lock per
#: metadata filename so the function and data stores don't contend).  Public
#: so a caller can assert the batch write gate publishes one lock per
#: filename rather than re-creating it per acquisition.
#: Reentrant: a caller may hold the lock across a compound operation whose
#: helpers take it again (the GA batch splices a stub and promotes its STATUS
#: through ``update_source_status`` inside the same critical section).
METADATA_WRITE_LOCKS: dict[str, threading.RLock] = {}
_METADATA_WRITE_LOCKS_LOCK = threading.Lock()

#: Per-thread reentrancy depth per resolved metadata path, so a nested acquisition
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

    Reentrant within one thread: a nested acquisition on the same filename
    yields without re-``flock``ing (the flock is held until the outermost
    exit), so a compound critical section can call helpers that lock again.
    """
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
    with _METADATA_WRITE_LOCKS_LOCK:
        if filename not in METADATA_WRITE_LOCKS:
            METADATA_WRITE_LOCKS[filename] = threading.RLock()
        lock = METADATA_WRITE_LOCKS[filename]
    depth: dict[str, int] | None = getattr(_METADATA_WRITE_DEPTH, "depth", None)
    if depth is None:
        depth = {}
        _METADATA_WRITE_DEPTH.depth = depth
    # Depth is per resolved path, not per filename: a nested lock on the
    # same-named file in another root must still take that root's flock.
    key = str(path)
    with lock:
        if depth.get(key, 0):
            # Reentrant: this thread already holds the lock and the flock.
            # Re-opening the sidecar and flocking a second fd would block
            # against the first, so only track the depth here.
            depth[key] += 1
            try:
                yield
            finally:
                depth[key] -= 1
            return
        depth[key] = 1
        try:
            with file_lock(path.with_suffix(path.suffix + ".lock")):
                yield
        finally:
            depth.pop(key, None)


#: Serializes in-memory metadata-doc cache mutations (``rebrew-functions.toml``
#: / ``rebrew-data.toml``).  ``rebrew verify --jobs N`` fills the cache from
#: workers while ``rebrew test`` / match / GA writers pop after STATUS
#: promotion — unguarded clear/pop vs fill races the shared dict.
_METADATA_DOC_CACHE_LOCK = threading.Lock()
#: Cap entries so a long-lived process that walks many project roots (or a
#: large pytest session with unique tmp_path TOMLs) cannot retain every
#: parsed table until exit.  Eviction is FIFO on insertion order.
_METADATA_DOC_CACHE_MAX = 64

#: ``(st_mtime_ns, st_size, st_ino)`` of a metadata TOML.  mtime alone misses
#: another process's rewrite inside one timestamp tick (coarse filesystems,
#: ``cp -p``); the atomic-rename writers always produce a new inode.
MetadataDocFingerprint = tuple[int, int, int]
MetadataDocCache = dict[Path, tuple[MetadataDocFingerprint, dict[tuple[str, int], dict[str, Any]]]]


def pop_metadata_doc_cache(
    cache: MetadataDocCache,
    path: Path,
) -> None:
    """Drop one entry from a metadata-doc cache under the shared lock."""
    with _METADATA_DOC_CACHE_LOCK:
        cache.pop(path, None)


def clear_metadata_doc_cache(
    cache: MetadataDocCache,
) -> None:
    """Clear a metadata-doc cache under the shared lock."""
    with _METADATA_DOC_CACHE_LOCK:
        cache.clear()


def load_metadata_doc(
    path: Path,
    cache: MetadataDocCache,
    description: str,
    *,
    deepcopy: bool = True,
    known_fields: frozenset[str] | None = None,
) -> dict[tuple[str, int], dict[str, Any]]:
    """Parse a qualified-key metadata TOML (``rebrew-functions.toml`` /
    ``rebrew-data.toml``) into ``{(module, va): fields}``.

    Shared by ``metadata.load_metadata`` and ``data_metadata.load_data_metadata``,
    which previously each hand-rolled the load→parse→mtime-cache pattern
    (with an inconsistent parser choice: tomlkit vs tomllib).  Reads use
    tomllib (strict, ~10x faster than tomlkit); round-trip preservation is
    only needed for WRITES, which still use tomlkit.

    *path* is resolved for stable cache keys.  *cache* is the caller's
    stat-fingerprinted in-memory cache (invalidated by write helpers).  Returns an
    empty dict when the file is missing or unparseable.  Pass *known_fields*
    (the store's closed field set, upper case) to have a hand-edited key that
    no reader understands reported instead of dropped.

    When *deepcopy* is True (default), each caller receives an isolated
    copy so mutating overlays cannot corrupt the cache.  Read-only
    overlays (annotation finalize, skip checks) pass ``deepcopy=False``
    to avoid cloning the whole table once per source file.
    """
    path = path.resolve()
    if not path.exists():
        pop_metadata_doc_cache(cache, path)
        return {}

    # Stat before reading: a rewrite racing the parse leaves newer content
    # under an older fingerprint, which the next stat replaces.
    try:
        st = path.stat()
    except OSError as exc:
        # A present-but-unreadable store is not an absent one: returning {}
        # reports "no metadata at all", so every STATUS / size / blocker
        # lookup reads as missing.
        logger.warning("Cannot stat %s %s: %s", description, path, exc)
        pop_metadata_doc_cache(cache, path)
        return {}
    current_fp: MetadataDocFingerprint = (st.st_mtime_ns, st.st_size, st.st_ino)
    with _METADATA_DOC_CACHE_LOCK:
        cached = cache.get(path)
        if cached is not None and cached[0] == current_fp:
            # Deep copy: callers mutate the entries they get (merge overlays,
            # status promotion), and an aliased dict would corrupt the cache.
            return copy.deepcopy(cached[1]) if deepcopy else cached[1]

    try:
        doc = load_tomllib(path)
    except Exception as exc:  # parser raises various types
        logger.warning("Failed to parse %s %s: %s", description, path, exc)
        return {}

    result = parse_metadata_doc(doc, known_fields=known_fields, source=str(path))
    with _METADATA_DOC_CACHE_LOCK:
        # Re-check: a writer may have invalidated (or another reader filled)
        # while we parsed — prefer a fresher entry if one landed.
        cached = cache.get(path)
        if cached is not None and cached[0] == current_fp:
            return copy.deepcopy(cached[1]) if deepcopy else cached[1]
        if len(cache) >= _METADATA_DOC_CACHE_MAX and path not in cache:
            oldest = next(iter(cache))
            cache.pop(oldest, None)
        cache[path] = (current_fp, result)
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
        return f"{unicodedata.normalize('NFC', module)}.{va_hex}"
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
    module, sep, address = key.rpartition(".")
    if not sep or address[:2].lower() != "0x":
        return None
    digits = address[2:]
    # int() also accepts underscores, Unicode digits, and trailing whitespace;
    # those spellings must not resolve to a VA other readers skip.
    if not digits or digits.strip("0123456789abcdefABCDEF"):
        return None
    return unicodedata.normalize("NFC", module), int(digits, 16)


def build_metadata_key_index(doc: dict[str, Any]) -> dict[tuple[str, int], str]:
    """Map ``(module, va)`` → existing key spelling for *doc*.

    Built once per batch write so :func:`resolve_metadata_key` is O(1) per
    update instead of O(n) (intake / verify STATUS sync grow as O(n²) without
    this when every new entry misses the canonical spelling and rescans).
    Rejects duplicate identities: updating only one spelling can leave a
    later table overriding the write, or resurrect a deleted field.
    """
    index: dict[tuple[str, int], str] = {}
    for existing in doc:
        parsed = parse_metadata_key(str(existing))
        if parsed is None:
            continue
        key = str(existing)
        if parsed in index:
            raise ValueError(
                f"duplicate metadata keys {index[parsed]!r} and {key!r} "
                f"resolve to {qualified_key(*parsed)!r}; consolidate them before writing"
            )
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

    Uses whatever spelling the store already has, and returns the canonical
    key when the entry is absent so callers can create it. Duplicate identities
    raise before any write. Shared by ``metadata.py`` and ``data_metadata.py``.

    Pass *index* (from :func:`build_metadata_key_index`) on batch writers so
    each resolve stays O(1); without it, build the checked index once for this
    single-entry write.
    """
    if module:
        module = unicodedata.normalize("NFC", module)
    canonical = qualified_key(module, va)
    want = (module, va)
    if index is None:
        index = build_metadata_key_index(doc)
    existing = index.get(want)
    if existing is not None and existing in doc:
        return existing
    return canonical


#: Entry keys reported per file in the unknown-key warning.  A file with
#: hundreds of typo'd keys is one mistake, not hundreds of lines of output.
_UNKNOWN_KEY_REPORT_MAX = 5


def parse_metadata_doc(
    doc: dict[str, Any],
    *,
    known_fields: frozenset[str] | None = None,
    source: str = "",
) -> dict[tuple[str, int], dict[str, Any]]:
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

    *known_fields* is the closed field set of the store, compared
    case-insensitively.  A hand-edited key outside it (``CFLAGSS``,
    ``TOOLCHIAN``) is dropped by every reader, so the function silently
    compiles with the wrong flags; the store's writers reject such a key
    already, and this makes a hand edit just as loud.  One warning per parse,
    naming *source* and the offending keys.
    """
    result: dict[tuple[str, int], dict[str, Any]] = {}
    first_key: dict[tuple[str, int], str] = {}
    unknown: dict[str, list[str]] = {}
    for key, value in doc.items():
        parsed = parse_metadata_key(key)
        if parsed is None or not isinstance(value, dict):
            continue
        if known_fields is not None:
            bad = sorted(
                str(f) for f in value if isinstance(f, str) and f.upper() not in known_fields
            )
            if bad:
                unknown.setdefault(qualified_key(parsed[0], parsed[1]), []).extend(bad)
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
    if unknown:
        shown = sorted(unknown.items())[:_UNKNOWN_KEY_REPORT_MAX]
        detail = ", ".join(f"{entry}: {sorted(set(keys))}" for entry, keys in shown)
        extra = f" (+{len(unknown) - len(shown)} more entries)" if len(unknown) > len(shown) else ""
        logger.warning(
            "%sunknown metadata field(s) ignored: %s%s — fix the key or rebrew never reads it",
            f"{source}: " if source else "",
            detail,
            extra,
        )
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
