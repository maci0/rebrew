"""Ordered reads, durable multi-backend writes and causal replica reconciliation."""

import contextlib
import functools
import logging
import threading
from collections import OrderedDict
from dataclasses import dataclass
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

from rebrew.metadata.sqlite import MetadataStorageError, MetadataUnavailableError
lazy from rebrew.metadata.files import METADATA_FILENAMES, TomlStore
lazy from rebrew.metadata.lazydoc import parse_roundtrip, render
lazy from rebrew.metadata.locking import project_transaction

if TYPE_CHECKING:
    from rebrew.metadata.storage import BackendFactory, Fingerprint, MetadataStore, Validator

STATE_PATH = ".rebrew/metadata-replication.toml"
JOURNAL_PATH = ".rebrew/metadata-journal.toml"
_ACTIVE = threading.local()
logger = logging.getLogger(__name__)


class MetadataConflictError(MetadataStorageError):
    """Replicas contain independent changes which cannot safely overwrite one another."""


#: Semantic digests by raw-content hash.  Parsing and normalizing a large store
#: costs seconds, and one operation digests the same text several times.
_DIGEST_MAX = 64
_DIGEST_LOCK = threading.Lock()
_DIGESTS: OrderedDict[tuple[str, bool], str] = OrderedDict()


def _digest(content: str, deleted: bool = False) -> str:
    """Hash semantic TOML values, independent of comments and fragment placement."""

    def normalized(value: Any) -> Any:
        if isinstance(value, dict):
            return ["table", sorted((key, normalized(item)) for key, item in value.items())]
        if isinstance(value, list):
            return ["array", [normalized(item) for item in value]]
        return [type(value).__name__, str(value)]

    key = (hashlib.sha256(content.encode()).hexdigest(), deleted)
    with _DIGEST_LOCK:
        cached = _DIGESTS.get(key)
        if cached is not None:
            _DIGESTS.move_to_end(key)
            return cached
    values = ["deleted"] if deleted else normalized(tomllib.loads(content))
    digest = hashlib.sha256(json.dumps(values, ensure_ascii=True).encode()).hexdigest()
    with _DIGEST_LOCK:
        _DIGESTS[key] = digest
        while len(_DIGESTS) > _DIGEST_MAX:
            _DIGESTS.popitem(last=False)
    return digest


def _toml_string(value: str) -> str:
    """A TOML basic string.  JSON escaping is valid TOML except for DEL, which TOML requires escaped."""
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def _render_state(records: dict[str, _Record], node: str) -> str:
    """Render a journal or replication-state document without per-character TOML escaping."""
    lines = ["format = 1"]
    if node:
        lines.append(f"node = {_toml_string(node)}")
    lines.append("")
    lines.append("[records]")
    for key, record in records.items():
        table = f"records.{_toml_string(key)}"
        lines += [
            "",
            f"[{table}]",
            f"updated_at_ns = {record.updated_at_ns}",
            f"content = {_toml_string(record.content)}",
            f"deleted = {'true' if record.deleted else 'false'}",
            f"digest = {_toml_string(record.digest)}",
            "",
            f"[{table}.clock]",
            *(f"{_toml_string(name)} = {revision}" for name, revision in record.clock.items()),
        ]
    return "\n".join(lines) + "\n"


def _parse_rendered(text: str) -> dict[str, Any] | None:
    """Read exactly the layout :func:`_render_state` writes; None for anything else.

    ``tomllib`` scans a basic string one character at a time in Python, which
    costs seconds per journal or state document carrying a copy of a large
    store.  These documents are written only by this module, so their strings
    are JSON-escaped and can be decoded by ``json``; any other layout (an older
    journal, a hand edit) is left to ``tomllib``.
    """

    def string(token: str) -> str | None:
        if not (token.startswith('"') and token.endswith('"')):
            return None
        try:
            value = json.loads(token)
        except ValueError:
            return None
        return value if isinstance(value, str) else None

    def integer(token: str) -> int | None:
        digits = token[1:] if token.startswith("-") else token
        return int(token) if digits.isdigit() and digits == str(int(digits)) else None

    lines = text.split("\n")
    if not lines or lines[-1] != "" or lines[0] != "format = 1":
        return None
    position = 1
    doc: dict[str, Any] = {"format": 1}
    if lines[position].startswith("node = "):
        node = string(lines[position][len("node = ") :])
        if node is None:
            return None
        doc["node"] = node
        position += 1
    if lines[position : position + 2] != ["", "[records]"]:
        return None
    position += 2
    records: dict[str, Any] = {}
    doc["records"] = records
    end = len(lines) - 1
    while position < end:
        block = lines[position : position + 8]
        if len(block) != 8 or block[0] != "" or block[6] != "":
            return None
        header, stamp, content, deleted, digest, clock_header = (
            block[1],
            block[2],
            block[3],
            block[4],
            block[5],
            block[7],
        )
        if not (header.startswith("[records.") and header.endswith("]")):
            return None
        key = string(header[len("[records.") : -1])
        if key is None or key in records or clock_header != f"[records.{_toml_string(key)}.clock]":
            return None
        row: dict[str, Any] = {}
        for line, name in (
            (stamp, "updated_at_ns"),
            (content, "content"),
            (deleted, "deleted"),
            (digest, "digest"),
        ):
            prefix = f"{name} = "
            if not line.startswith(prefix):
                return None
            token = line[len(prefix) :]
            if name == "updated_at_ns":
                value: Any = integer(token)
            elif name == "deleted":
                value = {"true": True, "false": False}.get(token)
            else:
                value = string(token)
            if value is None:
                return None
            row[name] = value
        clock: dict[str, int] = {}
        position += 8
        while position < end and lines[position] != "":
            node_token, separator, revision_token = lines[position].rpartition(" = ")
            node_name = string(node_token)
            revision = integer(revision_token)
            if not separator or node_name is None or revision is None or node_name in clock:
                return None
            clock[node_name] = revision
            position += 1
        row["clock"] = clock
        records[key] = row
    return doc


@dataclass(frozen=True)
class _Record:
    clock: dict[str, int]
    updated_at_ns: int
    content: str
    deleted: bool

    @functools.cached_property
    def digest(self) -> str:
        return _digest(self.content, self.deleted)


#: Parsed journal and state documents by store fingerprint.  Each one carries a
#: copy of every replicated document, and one operation loads them repeatedly.
_LOADED_MAX = 8
_LOADED_LOCK = threading.Lock()
_LOADED: OrderedDict[tuple[str, str, Fingerprint], tuple[dict[str, _Record], str]] = OrderedDict()


#: Resolved replica views by the fingerprints of every input (journal, each read
#: backend's document and state).  Resolving one reads and hashes the document.
_VIEWS_MAX = 32
_VIEWS_LOCK = threading.Lock()
_VIEWS: OrderedDict[tuple[object, ...], _Record | None] = OrderedDict()


def _load(store: MetadataStore) -> tuple[dict[str, _Record], str]:
    fingerprint = store.fingerprint()
    if not fingerprint:
        return {}, ""
    key = (str(store.location), str(store.path), fingerprint)
    with _LOADED_LOCK:
        cached = _LOADED.get(key)
        if cached is not None:
            _LOADED.move_to_end(key)
            return dict(cached[0]), cached[1]
    records, node = _parse_state(store)
    if store.fingerprint() == fingerprint:
        with _LOADED_LOCK:
            _LOADED[key] = (records, node)
            while len(_LOADED) > _LOADED_MAX:
                _LOADED.popitem(last=False)
    return dict(records), node


def _parse_state(store: MetadataStore) -> tuple[dict[str, _Record], str]:
    text = store.text()
    if text is None:
        return {}, ""
    doc = _parse_rendered(text)
    if doc is None:
        doc = store.read("metadata replication state")
    if not doc:
        return {}, ""
    if (
        set(doc) - {"format", "node", "records"}
        or type(doc.get("format")) is not int
        or doc.get("format") != 1
    ):
        raise MetadataStorageError("invalid metadata replication state")
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
            or set(row) != {"clock", "updated_at_ns", "content", "deleted", "digest"}
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
        record = _Record(row["clock"], row["updated_at_ns"], row["content"], row["deleted"])
        if record.digest != row["digest"]:
            raise MetadataStorageError("metadata replication digest mismatch")
        records[key] = record
    return records, node


def _save(store: MetadataStore, records: dict[str, _Record], node: str = "") -> None:
    store.write_text(_render_state(records, node), "metadata replication state")


def _observed(store: MetadataStore, recorded: _Record | None) -> _Record | None:
    text = store.text()
    exists = text is not None
    if not exists and recorded is None:
        return None
    content = text or ""
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
    if len({r.digest for r in maxima}) != 1:
        raise MetadataConflictError(
            f"conflicting metadata replicas for {key}; preserve and review both copies"
        )
    chosen = max(maxima, key=lambda record: record.updated_at_ns)
    clock: dict[str, int] = {}
    for record in maxima:
        for node, revision in record.clock.items():
            clock[node] = max(clock.get(node, 0), revision)
    return _Record(clock, chosen.updated_at_ns, chosen.content, chosen.deleted)


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

    def reconcile(self) -> None:
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
        for key in sorted(keys):
            if key not in self.changed:
                record = self.collect(key)
                if record is not None:
                    self.records[key] = record

    def validate(self) -> None:
        if self.validator is not None:
            for key, record in self.records.items():
                if not record.deleted:
                    self.validator(self.route.root / key, tomllib.loads(record.content))

    def finish(self) -> None:
        self.reconcile()
        self.validate()
        if self.records:
            # This local write-ahead journal is the durable commit before replica publication.
            _save(self.journal, self.records, self.node)
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
                _save(self.route.state(name), self.records)
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

    def _read_from[T](self, operation: Callable[[MetadataStore, dict[str, _Record]], T]) -> T:
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
                records, _ = _load(self.state(name))
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
                        _VIEWS.move_to_end(token)
                        return _VIEWS[token]
        local, _ = _load(TomlStore(self.root / JOURNAL_PATH, self.root))

        def view(store: MetadataStore, records: dict[str, _Record]) -> _Record | None:
            candidates = [local[self.key]] if self.key in local else []
            observed = _observed(store, records.get(self.key))
            if observed is not None:
                candidates.append(observed)
            return _winner(self.key, candidates)

        record = self._read_from(view)
        if token is not None and self._inputs_token() == token:
            with _VIEWS_LOCK:
                _VIEWS[token] = record
                while len(_VIEWS) > _VIEWS_MAX:
                    _VIEWS.popitem(last=False)
        return record

    def read(
        self, description: str, *, validate: Validator | None = None, roundtrip: bool = False
    ) -> dict[str, Any]:
        record = self._view()
        if record is None or record.deleted:
            return {}
        if roundtrip:
            return parse_roundtrip(record.content, validate)
        doc = tomllib.loads(record.content)
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

        return self._read_from(discover)

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
            finally:
                session.close()
        else:
            with self.transaction():
                session = _ACTIVE.sessions[self.root]
                session.validator = validate
        items = [
            {"backend": name, "pending": name in session.pending, "documents": len(session.records)}
            for name in self.write_backends
        ]
        return {"items": items, "total": len(items), "dry_run": dry_run}

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
