"""Ordered reads, durable multi-backend writes and causal replica reconciliation."""

import contextlib
import functools
import logging
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
lazy import hashlib
lazy import json
lazy import socket
lazy import time
lazy import tomllib
lazy import uuid
lazy from collections.abc import Callable, Iterator
lazy from pathlib import Path
lazy from typing import Any

from cachetools import LRUCache
lazy import rtoml

from rebrew.metadata.sqlite import MetadataStorageError, MetadataUnavailableError
lazy from rebrew.metadata import lazydoc, rendered_toml
lazy from rebrew.metadata.files import METADATA_FILENAMES, TomlStore
lazy from rebrew.metadata.lazydoc import parse_roundtrip, render
lazy from rebrew.metadata.locking import project_transaction

if TYPE_CHECKING:
    from rebrew.metadata.storage import BackendFactory, Fingerprint, MetadataStore, Validator

STATE_PATH = ".rebrew/metadata-replication.toml"
JOURNAL_PATH = ".rebrew/metadata-journal.toml"
#: ``format`` of the journal and replication-state documents.  2 requires
#: ``content_sha256`` in every record; 1 is read (6.59.0 wrote the field under
#: it, earlier releases did not) and rewritten as 2 by the next write.
_STATE_FORMAT = 2
_BASE_FIELDS = frozenset({"clock", "updated_at_ns", "content", "deleted", "digest"})
#: Required and optional record fields by ``format``.
_RECORD_FIELDS: dict[int, tuple[frozenset[str], frozenset[str]]] = {
    1: (_BASE_FIELDS, frozenset({"content_sha256"})),
    2: (_BASE_FIELDS | {"content_sha256"}, frozenset()),
}
_ACTIVE = threading.local()
logger = logging.getLogger(__name__)


class MetadataConflictError(MetadataStorageError):
    """Replicas contain independent changes which cannot safely overwrite one another."""


#: Semantic digests by raw-content hash.  Parsing and normalizing a large store
#: costs seconds, and one operation digests the same text several times.
_DIGEST_MAX = 64
_DIGEST_LOCK = threading.Lock()
_DIGESTS: LRUCache[tuple[str, bool], str] = LRUCache(maxsize=_DIGEST_MAX)

#: Normalized JSON of one top-level record by the record's exact text.  A write
#: changes a few records of a store, so the next digest of it normalizes only
#: those.  Bounded in characters of JSON, above the largest store's (33 MB for
#: guild-rebrew's functions store).
_RECORD_JSON_MAX_CHARS = 96 * 1024 * 1024
_RECORD_JSON: LRUCache[str, str] = LRUCache(maxsize=_RECORD_JSON_MAX_CHARS, getsizeof=len)


def _content_sha256(content: str) -> str:
    """Raw SHA-256 of a replicated document's text (no parse)."""
    return hashlib.sha256(content.encode()).hexdigest()


def _normalized(value: Any) -> Any:
    if isinstance(value, dict):
        return ["table", sorted((key, _normalized(item)) for key, item in value.items())]
    if isinstance(value, list):
        return ["array", [_normalized(item) for item in value]]
    return [type(value).__name__, str(value)]


def _normalized_json(content: str) -> str:
    """``json.dumps(_normalized(tomllib.loads(content)), ensure_ascii=True)``.

    A large document is assembled from the JSON of each top-level record, cached
    by the record's text: a dict normalizes to its items sorted by key, so the
    document's JSON is the records' JSON in key order.
    """
    split = lazydoc.split_records(content) if len(content) >= lazydoc.LAZY_MIN_CHARS else None
    if split is None:
        return json.dumps(_normalized(rendered_toml.loads(content)), ensure_ascii=True)
    _preamble, head, records = split
    items = [
        (key, json.dumps([key, _normalized(value)], ensure_ascii=True))
        for key, value in head.items()
    ]
    with _DIGEST_LOCK:
        known = [_RECORD_JSON.get(raw) for _key, raw, _value in records]
    computed: list[tuple[str, str]] = []
    for (key, raw, value), item in zip(records, known, strict=True):
        if item is None:
            item = json.dumps([key, _normalized(value)], ensure_ascii=True)
            computed.append((raw, item))
        items.append((key, item))
    if computed:
        with _DIGEST_LOCK:
            for raw, item in computed:
                if raw not in _RECORD_JSON and len(item) <= _RECORD_JSON_MAX_CHARS:
                    _RECORD_JSON[raw] = item
    items.sort(key=lambda pair: pair[0])
    return '["table", [' + ", ".join(item for _key, item in items) + "]]"


def _digest(content: str, deleted: bool = False) -> str:
    """Hash semantic TOML values, independent of comments and fragment placement."""
    key = (hashlib.sha256(content.encode()).hexdigest(), deleted)
    with _DIGEST_LOCK:
        cached = _DIGESTS.get(key)
        if cached is not None:
            return cached
    values = json.dumps(["deleted"], ensure_ascii=True) if deleted else _normalized_json(content)
    digest = hashlib.sha256(values.encode()).hexdigest()
    with _DIGEST_LOCK:
        _DIGESTS[key] = digest
    return digest


def _render_state(records: dict[str, _Record], node: str, body: str | None = None) -> str:
    """Render a journal or replication-state document via ``rtoml``.

    *body* is :func:`_render_records` of *records*, when the caller already has it.
    """
    header: dict[str, Any] = {"format": _STATE_FORMAT}
    if node:
        header["node"] = node
    rendered_body = _render_records(records) if body is None else body
    return rtoml.dumps(header) + "\n" + rendered_body


def _render_records(records: dict[str, _Record]) -> str:
    """The record tables of a journal or state document; a commit writes the same ones to each."""
    payload: dict[str, Any] = {}
    for key, record in records.items():
        payload[key] = {
            "updated_at_ns": record.updated_at_ns,
            "content": record.content,
            "deleted": record.deleted,
            "digest": record.digest,
            "content_sha256": _content_sha256(record.content),
            "clock": dict(record.clock),
        }
    return rtoml.dumps({"records": payload})


def _parse_rendered(
    text: str,
    known_records: dict[str, _Record] | None = None,
    *,
    content_lines: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """Parse a rendered journal or replication-state TOML document via ``rtoml``.

    Returns ``None`` on parse failure so the caller falls back to the store
    reader and surfaces its standard error contract.
    """
    del known_records, content_lines
    try:
        doc = rtoml.loads(text)
    except rtoml.TomlParsingError:
        return None
    return doc if isinstance(doc, dict) else None


@dataclass(frozen=True)
class _Record:
    clock: dict[str, int]
    updated_at_ns: int
    content: str
    deleted: bool
    content_line: str | None = field(default=None, compare=False, repr=False)

    @functools.cached_property
    def content_sha256(self) -> str:
        return _content_sha256(self.content)

    @functools.cached_property
    def digest(self) -> str:
        return _digest(self.content, self.deleted)


#: Parsed journal and state documents by store fingerprint.  Each one carries a
#: copy of every replicated document, and one operation loads them repeatedly.
_LOADED_MAX = 8
_LOADED_LOCK = threading.Lock()
_LOADED: LRUCache[tuple[str, str, Fingerprint], tuple[dict[str, _Record], str]] = LRUCache(
    maxsize=_LOADED_MAX
)


#: Resolved replica views by the fingerprints of every input (journal, each read
#: backend's document and state).  Resolving one reads and hashes the document.
_VIEWS_MAX = 32
_VIEWS_LOCK = threading.Lock()
_VIEWS: LRUCache[tuple[object, ...], _Record | None] = LRUCache(maxsize=_VIEWS_MAX)


def _load(
    store: MetadataStore, known_records: dict[str, _Record] | None = None
) -> tuple[dict[str, _Record], str]:
    fingerprint = store.fingerprint()
    if not fingerprint:
        return {}, ""
    key = (str(store.location), str(store.path), fingerprint)
    with _LOADED_LOCK:
        cached = _LOADED.get(key)
        if cached is not None:
            return dict(cached[0]), cached[1]
    records, node = _parse_state(store, known_records)
    if store.fingerprint() == fingerprint:
        with _LOADED_LOCK:
            _LOADED[key] = (records, node)
    return dict(records), node


def _parse_state(
    store: MetadataStore, known_records: dict[str, _Record] | None
) -> tuple[dict[str, _Record], str]:
    text = store.text()
    if text is None:
        return {}, ""
    # Only the journal supplies exact source lines for later replica reads.
    content_lines: dict[str, str] | None = {} if store.path == store.root / JOURNAL_PATH else None
    doc = _parse_rendered(text, known_records, content_lines=content_lines)
    if doc is None:
        content_lines = None
        doc = store.read("metadata replication state")
    if not doc:
        return {}, ""
    number = doc.get("format")
    if type(number) is int and number > _STATE_FORMAT:
        raise MetadataStorageError(
            f"metadata replication state format {number} is newer than this rebrew reads"
            f" ({_STATE_FORMAT}); upgrade rebrew"
        )
    if (
        set(doc) - {"format", "node", "records"}
        or type(number) is not int
        or number not in _RECORD_FIELDS
    ):
        raise MetadataStorageError("invalid metadata replication state")
    fields, optional = _RECORD_FIELDS[number]
    node = doc.get("node", "")
    if not isinstance(node, str) or not isinstance(doc.get("records"), dict):
        raise MetadataStorageError("invalid metadata replication state")
    records = {}
    for key, row in doc["records"].items():
        path = store.root / key
        if (
            Path(key).is_absolute()
            or ".." in Path(key).parts
            or not path.resolve().is_relative_to(store.root)
            or path.name not in METADATA_FILENAMES
        ):
            raise MetadataStorageError("invalid metadata replication document path")
        if (
            not isinstance(row, dict)
            or set(row) - optional != fields
            or not isinstance(row.get("content_sha256", ""), str)
            or not isinstance(row["clock"], dict)
            or any(
                not isinstance(k, str) or type(v) is not int or v < 0
                for k, v in row["clock"].items()
            )
            or type(row["updated_at_ns"]) is not int
            or row["updated_at_ns"] < 0
            or not isinstance(row["content"], str)
            or type(row["deleted"]) is not bool
        ):
            raise MetadataStorageError("invalid metadata replication record")
        content = row["content"]
        known = known_records.get(key) if known_records is not None else None
        # The journal may carry an identical copy of this replica's text.
        if known is not None and type(content) is str and known.content == content:
            content = known.content
        else:
            known = None
        record = _Record(
            row["clock"],
            row["updated_at_ns"],
            content,
            row["deleted"],
            content_lines.get(key) if content_lines is not None else None,
        )
        if "content_sha256" in row:
            # The raw hash proves the content is what the digest was computed
            # from, so the stored digest stands without parsing the document.
            if known is not None:
                record.__dict__["content_sha256"] = known.content_sha256
            if record.content_sha256 != row["content_sha256"]:
                raise MetadataStorageError("metadata replication content hash mismatch")
            record.__dict__["digest"] = row["digest"]
        elif record.digest != row["digest"]:
            raise MetadataStorageError("metadata replication digest mismatch")
        records[key] = record
    return records, node


def _save(
    store: MetadataStore, records: dict[str, _Record], node: str = "", body: str | None = None
) -> None:
    store.write_text(_render_state(records, node, body), "metadata replication state")


def _observed(store: MetadataStore, recorded: _Record | None) -> _Record | None:
    text = store.text()
    exists = text is not None
    if not exists and recorded is None:
        return None
    content = text or ""
    if recorded is not None and recorded.deleted == (not exists) and recorded.content == content:
        # Same text, same digest: skip parsing the document to hash it.
        return recorded
    digest = _digest(content, not exists)
    if recorded is not None and digest == recorded.digest:
        return recorded
    clock = dict(recorded.clock) if recorded else {f"untracked:{store.name}:{digest}": 1}
    if recorded is not None:
        # An edit outside the router is independent of other replicas' pending writes.
        node = f"external:{store.name}:{digest}"
        clock[node] = clock.get(node, 0) + 1
    return _Record(
        clock,
        max(time.time_ns(), recorded.updated_at_ns + 1) if recorded else 0,
        content,
        not exists,
    )


def _winner(key: str, records: list[_Record]) -> _Record | None:
    if not records:
        return None
    maxima = [
        r
        for r in records
        if not any(
            all(other.clock.get(k, 0) >= v for k, v in r.clock.items())
            and any(v > r.clock.get(k, 0) for k, v in other.clock.items())
            for other in records
        )
    ]
    if len(maxima) > 1 and len({r.digest for r in maxima}) != 1:
        raise MetadataConflictError(
            f"conflicting metadata replicas for {key}; preserve and review both copies"
        )
    chosen = max(maxima, key=lambda record: record.updated_at_ns)
    clock: dict[str, int] = {}
    for record in maxima:
        for node, revision in record.clock.items():
            clock[node] = max(clock.get(node, 0), revision)
    merged = _Record(clock, chosen.updated_at_ns, chosen.content, chosen.deleted)
    if "digest" in chosen.__dict__:
        # Same content and deletion flag: the digest carries over unparsed.
        merged.__dict__["digest"] = chosen.__dict__["digest"]
    return merged


class _Session:
    def __init__(self, route: RoutedStore) -> None:
        self.route = route
        self.journal = TomlStore(route.root / JOURNAL_PATH, route.root)
        self.records, self.node = _load(self.journal)
        self.scope = hashlib.sha256(f"{socket.gethostname()}:{route.root}".encode()).hexdigest()[
            :16
        ]
        if self.node:
            self.node = self.node.split(":", 1)[0] + ":" + self.scope
        self.states: dict[str, dict[str, _Record]] = {}
        self.contexts: dict[str, contextlib.ExitStack] = {}
        self.pending: set[str] = set()
        self.changed: set[str] = set()
        self.committed = False
        self.report_divergence = False
        self.divergence: dict[str, list[str]] | None = None
        self.validator: Callable[[Path, dict[str, Any]], None] | None = None

    def open(self, *, transactional: bool = True) -> None:
        for name in sorted(self.route.factories):
            stack = contextlib.ExitStack()
            try:
                state = self.route.state(name)
                if transactional and name in self.route.write_backends:
                    stack.enter_context(state.transaction())
                self.states[name], _ = _load(state)
                self.contexts[name] = stack
            except OSError, MetadataUnavailableError:
                stack.close()
                self.pending.add(name)
            except BaseException:
                stack.close()
                raise

    def collect(self, key: str) -> _Record | None:
        candidates = [self.records[key]] if key in self.records else []
        for name in self.contexts:
            if name in self.pending:
                continue
            try:
                record = _observed(self.route.store(name, key), self.states[name].get(key))
            except OSError, MetadataUnavailableError:
                self.pending.add(name)
                continue
            if record is not None:
                candidates.append(record)
        return _winner(key, candidates)

    def stage(self, key: str, content: str | None) -> None:
        prior = self.collect(key)
        deleted = content is None
        if (
            prior is not None
            and prior.digest == _digest(content or "", deleted)
            and prior.content == (content or "")
        ):
            self.records[key] = prior
            return
        self.node = self.node or uuid.uuid4().hex + ":" + self.scope
        clock = dict(prior.clock) if prior else {}
        clock[self.node] = clock.get(self.node, 0) + 1
        self.records[key] = _Record(
            clock,
            max(time.time_ns(), prior.updated_at_ns + 1) if prior else time.time_ns(),
            content or "",
            deleted,
        )
        self.changed.add(key)

    def keys(self) -> set[str]:
        """Every document key any replica, receipt or the journal knows."""
        keys = set(self.records)
        for name, records in self.states.items():
            keys.update(records)
            if name not in self.pending:
                try:
                    keys.update(
                        path.relative_to(self.route.root).as_posix()
                        for path in self.route.store(name, "rebrew-functions.toml").documents(
                            recursive=True
                        )
                    )
                except OSError, MetadataUnavailableError:
                    self.pending.add(name)
        return keys

    def reconcile(self) -> None:
        for key in sorted(self.keys()):
            if key not in self.changed:
                record = self.collect(key)
                if record is not None:
                    self.records[key] = record

    def adopt(self, source: str) -> None:
        """Make *source*'s documents the state of every replica, whatever the others hold.

        Each adopted record carries a clock above every replica's, so no
        replica's later reconciliation can win over it.
        """
        if source not in self.contexts or source in self.pending:
            raise MetadataUnavailableError(f"{source} replica is unavailable")
        for key in sorted(self.keys()):
            text = self.route.store(source, key).text()
            candidates = [self.records[key]] if key in self.records else []
            for name in self.contexts:
                if name not in self.pending:
                    seen = _observed(self.route.store(name, key), self.states[name].get(key))
                    if seen is not None:
                        candidates.append(seen)
            digest = _digest(text or "", text is None)
            if all(c.digest == digest and c.deleted == (text is None) for c in candidates):
                continue
            clock: dict[str, int] = {}
            for candidate in candidates:
                for node, revision in candidate.clock.items():
                    clock[node] = max(clock.get(node, 0), revision)
            self.node = self.node or uuid.uuid4().hex + ":" + self.scope
            clock[self.node] = clock.get(self.node, 0) + 1
            newest = max((c.updated_at_ns for c in candidates), default=0)
            self.records[key] = _Record(
                clock, max(time.time_ns(), newest + 1), text or "", text is None
            )
            self.changed.add(key)

    def diverged(self) -> dict[str, list[str]]:
        """Per write backend, the documents whose replica text differs from the resolved record."""
        found: dict[str, list[str]] = {}
        for name in self.route.write_backends:
            if name not in self.contexts or name in self.pending:
                continue
            differing = []
            for key, record in sorted(self.records.items()):
                seen = _observed(self.route.store(name, key), self.states[name].get(key))
                same = (
                    record.deleted
                    if seen is None
                    else seen.deleted == record.deleted and seen.digest == record.digest
                )
                if not same:
                    differing.append(key)
            found[name] = differing
        return found

    def validate(self) -> None:
        if self.validator is not None:
            for key, record in self.records.items():
                if not record.deleted:
                    self.validator(self.route.root / key, tomllib.loads(record.content))

    def finish(self) -> None:
        self.reconcile()
        self.validate()
        if self.report_divergence:
            self.divergence = self.diverged()
        body = _render_records(self.records)
        if self.records:
            # This local write-ahead journal is the durable commit before replica publication.
            _save(self.journal, self.records, self.node, body)
        self.committed = True
        for name in self.route.write_backends:
            if name not in self.contexts or name in self.pending:
                continue
            try:
                for key, record in self.records.items():
                    store = self.route.store(name, key)
                    current = _observed(store, self.states[name].get(key))
                    if current is not None:
                        winner = _winner(key, [record, current])
                        if winner is not None and winner.digest != record.digest:
                            raise MetadataConflictError(
                                f"metadata replica changed during publication: {key}"
                            )
                    if (
                        current is None
                        or current.digest != record.digest
                        or current.content != record.content
                    ):
                        if record.deleted:
                            store.remove()
                        else:
                            store.write_text(record.content, "metadata replication")
                _save(self.route.state(name), self.records, body=body)
                self.contexts.pop(name).close()
            except (OSError, MetadataStorageError) as exc:
                # The journal already holds the commit, so a replica that
                # refuses publication must not abort the writer.  The cause
                # used to stop at the backend name, which left a disk-full
                # replica and a conflict looking the same in the log.
                logger.warning(
                    "metadata replica %s refused publication (%s: %s); "
                    "the recovery journal holds the commit",
                    name,
                    type(exc).__name__,
                    exc,
                )
                self.pending.add(name)
                stack = self.contexts.pop(name, None)
                if stack is not None:
                    stack.__exit__(type(exc), exc, exc.__traceback__)
        if self.pending:
            logger.warning(
                "metadata committed to recovery journal; reconciliation pending for: %s",
                ", ".join(sorted(self.pending)),
            )

    def close(self, error: BaseException | None = None) -> None:
        for name, stack in reversed(list(self.contexts.items())):
            cause = error or (
                MetadataUnavailableError("replica unavailable") if name in self.pending else None
            )
            try:
                stack.__exit__(
                    type(cause) if cause else None, cause, cause.__traceback__ if cause else None
                )
            except OSError, MetadataStorageError:
                if not self.committed and error is None:
                    raise
                self.pending.add(name)
        self.contexts.clear()


class RoutedStore:
    """Abstract metadata operations over ordered readers and replicated writers."""

    def __init__(
        self,
        path: Path,
        root: Path,
        read_backends: tuple[str, ...],
        write_backends: tuple[str, ...],
        factories: dict[str, BackendFactory],
    ) -> None:
        self.path, self.root = path, root
        self.key = path.relative_to(root).as_posix()
        self.read_backends, self.write_backends = read_backends, write_backends
        self.factories = factories
        self.name = read_backends[0]
        self.location = self.store(self.name, self.key).location

    def store(self, name: str, key: str) -> MetadataStore:
        return self.factories[name](self.root / key, self.root)

    def state(self, name: str) -> MetadataStore:
        return self.store(name, STATE_PATH)

    def _read_from[T](
        self, operation: Callable[[MetadataStore, dict[str, _Record]], T], local: dict[str, _Record]
    ) -> T:
        errors: list[str] = []
        for position, name in enumerate(self.read_backends):
            try:
                store = self.store(name, self.key)
                if position < len(self.read_backends) - 1 and not store.provisioned():
                    # An empty preferred backend is authoritative, but one that was never
                    # created (a fresh clone holding only the TOML replica) is not: it
                    # would answer every read with nothing and the next write would
                    # publish a document holding only that write.
                    raise MetadataUnavailableError(f"{name} storage not created yet")
                records, _ = _load(self.state(name), local)
                return operation(store, records)
            except (OSError, MetadataUnavailableError) as exc:
                errors.append(f"{name}: {exc}")
                continue
        raise MetadataUnavailableError(
            f"all configured metadata read backends are unavailable: {'; '.join(errors)}"
        )

    def _inputs_token(self) -> tuple[object, ...] | None:
        """Cheap change token for every input of the resolved view; None if unreadable."""
        try:
            return (
                str(self.root),
                self.key,
                TomlStore(self.root / JOURNAL_PATH, self.root).fingerprint(),
                tuple(
                    (name, self.store(name, self.key).fingerprint(), self.state(name).fingerprint())
                    for name in self.read_backends
                ),
            )
        except OSError, MetadataUnavailableError:
            return None

    def _view(self) -> _Record | None:
        session: _Session | None = getattr(_ACTIVE, "sessions", {}).get(self.root)
        if session is not None:
            if self.key in session.changed:
                return session.records[self.key]
            token = None
        else:
            # Resolving the view reads and hashes the whole document; callers such
            # as lint ask for a fingerprint once per source file.
            token = self._inputs_token()
            if token is not None:
                with _VIEWS_LOCK:
                    if token in _VIEWS:
                        return _VIEWS[token]
        local, _ = _load(TomlStore(self.root / JOURNAL_PATH, self.root))

        def view(store: MetadataStore, records: dict[str, _Record]) -> _Record | None:
            candidates = [local[self.key]] if self.key in local else []
            observed = _observed(store, records.get(self.key))
            if observed is not None:
                candidates.append(observed)
            return _winner(self.key, candidates)

        record = self._read_from(view, local)
        if token is not None and self._inputs_token() == token:
            with _VIEWS_LOCK:
                _VIEWS[token] = record
        return record

    def read(
        self, description: str, *, validate: Validator | None = None, roundtrip: bool = False
    ) -> dict[str, Any]:
        record = self._view()
        if record is None or record.deleted:
            return {}
        if roundtrip:
            return parse_roundtrip(record.content, validate)
        doc = lazydoc.loads(record.content)
        if validate is not None:
            validate(doc)
        return doc

    def exists(self) -> bool:
        record = self._view()
        return record is not None and not record.deleted

    def snapshot(self) -> bytes | None:
        record = self._view()
        return record.content.encode() if record is not None and not record.deleted else None

    def digest(self) -> str | None:
        content = self.snapshot()
        return hashlib.sha256(content).hexdigest() if content is not None else None

    def fingerprint(self) -> Fingerprint:
        record = self._view()
        if record is None or record.deleted:
            return ()
        return ((self.key, record.updated_at_ns, int(record.digest, 16), 0, 1),)

    def inputs(self) -> tuple[Path, ...]:
        return tuple(
            sorted(
                {
                    self.root / JOURNAL_PATH,
                    *(
                        path
                        for name in self.read_backends
                        for path in self.store(name, self.key).inputs()
                    ),
                }
            )
        )

    def documents(self, *, recursive: bool = False) -> tuple[Path, ...]:
        local, _ = _load(TomlStore(self.root / JOURNAL_PATH, self.root))

        def discover(store: MetadataStore, records: dict[str, _Record]) -> tuple[Path, ...]:
            keys = (
                {
                    path.relative_to(self.root).as_posix()
                    for path in store.documents(recursive=recursive)
                }
                | set(local)
                | set(records)
            )
            paths = []
            for key in sorted(keys):
                path = self.root / key
                if not path.is_relative_to(self.path.parent) or (
                    not recursive and path.parent != self.path.parent
                ):
                    continue
                candidates = [local[key]] if key in local else []
                observed = _observed(self.store(store.name, key), records.get(key))
                if observed is not None:
                    candidates.append(observed)
                record = _winner(key, candidates)
                if record is not None and not record.deleted:
                    paths.append(path)
            return tuple(paths)

        return self._read_from(discover, local)

    def reconcile(
        self,
        *,
        dry_run: bool = False,
        validate: Callable[[Path, dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """Repair available replicas; leave unavailable destinations durably queued."""
        if dry_run:
            session = _Session(self)
            session.validator = validate
            try:
                session.open(transactional=False)
                session.reconcile()
                session.validate()
                session.divergence = session.diverged()
            finally:
                session.close()
        else:
            with self.transaction():
                session = _ACTIVE.sessions[self.root]
                session.validator = validate
                session.report_divergence = True
        diverged = session.divergence or {}
        items = [
            {
                "backend": name,
                "pending": name in session.pending,
                "documents": len(session.records),
                "diverged": diverged.get(name, []),
            }
            for name in self.write_backends
        ]
        return {"items": items, "total": len(items), "dry_run": dry_run}

    def adopt(self, source: str) -> None:
        """Publish *source* backend's documents to every other replica, replacing what they hold."""
        with self.transaction():
            _ACTIVE.sessions[self.root].adopt(source)

    def write(self, doc: dict[str, Any], description: str) -> None:
        self.write_text(render(doc) or "\n", description)

    def text(self) -> str | None:
        record = self._view()
        return record.content if record is not None and not record.deleted else None

    def write_text(self, content: str, description: str) -> None:
        with self.transaction():
            _ACTIVE.sessions[self.root].stage(self.key, content)

    def provisioned(self) -> bool:
        return any(self.store(name, self.key).provisioned() for name in self.read_backends)

    def remove(self) -> None:
        with self.transaction():
            _ACTIVE.sessions[self.root].stage(self.key, None)

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        with project_transaction(self.root, self.path.name):
            sessions: dict[Path, _Session] | None = getattr(_ACTIVE, "sessions", None)
            if sessions is None:
                sessions = {}
                _ACTIVE.sessions = sessions
            if self.root in sessions:
                yield
                return
            session = _Session(self)
            sessions[self.root] = session
            error: BaseException | None = None
            try:
                session.open()
                yield
                session.finish()
            except BaseException as exc:
                error = exc
                raise
            finally:
                try:
                    session.close(error)
                finally:
                    sessions.pop(self.root, None)
