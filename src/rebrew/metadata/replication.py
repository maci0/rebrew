"""Ordered reads, durable multi-backend writes and causal replica reconciliation."""

import contextlib
import logging
import threading
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

lazy import tomlkit

from rebrew.metadata.sqlite import MetadataStorageError, MetadataUnavailableError
lazy from rebrew.metadata.files import METADATA_FILENAMES, TomlStore
lazy from rebrew.metadata.locking import project_transaction

if TYPE_CHECKING:
    from rebrew.metadata.storage import BackendFactory, Fingerprint, MetadataStore, Validator

STATE_PATH = ".rebrew/metadata-replication.toml"
JOURNAL_PATH = ".rebrew/metadata-journal.toml"
_ACTIVE = threading.local()
logger = logging.getLogger(__name__)


class MetadataConflictError(MetadataStorageError):
    """Replicas contain independent changes which cannot safely overwrite one another."""


def _digest(content: str, deleted: bool = False) -> str:
    """Hash semantic TOML values, independent of comments and fragment placement."""

    def normalized(value: Any) -> Any:
        if isinstance(value, dict):
            return ["table", sorted((key, normalized(item)) for key, item in value.items())]
        if isinstance(value, list):
            return ["array", [normalized(item) for item in value]]
        return [type(value).__name__, str(value)]

    values = ["deleted"] if deleted else normalized(tomllib.loads(content))
    return hashlib.sha256(json.dumps(values, ensure_ascii=True).encode()).hexdigest()


@dataclass(frozen=True)
class _Record:
    clock: dict[str, int]
    updated_at_ns: int
    content: str
    deleted: bool

    @property
    def digest(self) -> str:
        return _digest(self.content, self.deleted)

    def document(self) -> dict[str, Any]:
        return {
            "clock": self.clock,
            "updated_at_ns": self.updated_at_ns,
            "content": self.content,
            "deleted": self.deleted,
            "digest": self.digest,
        }


def _load(store: MetadataStore) -> tuple[dict[str, _Record], str]:
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
    doc: dict[str, Any] = {"format": 1, "records": {k: v.document() for k, v in records.items()}}
    if node:
        doc["node"] = node
    store.write(doc, "metadata replication state")


def _observed(store: MetadataStore, recorded: _Record | None) -> _Record | None:
    exists = store.exists()
    if not exists and recorded is None:
        return None
    content = tomlkit.dumps(store.read("metadata replica", roundtrip=True)) if exists else ""
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
                            store.write(tomlkit.parse(record.content), "metadata replication")
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
        for name in self.read_backends:
            try:
                records, _ = _load(self.state(name))
                return operation(self.store(name, self.key), records)
            except (OSError, MetadataUnavailableError) as exc:
                errors.append(f"{name}: {exc}")
                continue
        raise MetadataUnavailableError(
            f"all configured metadata read backends are unavailable: {'; '.join(errors)}"
        )

    def _view(self) -> _Record | None:
        session: _Session | None = getattr(_ACTIVE, "sessions", {}).get(self.root)
        if session is not None and self.key in session.changed:
            return session.records[self.key]
        local, _ = _load(TomlStore(self.root / JOURNAL_PATH, self.root))

        def view(store: MetadataStore, records: dict[str, _Record]) -> _Record | None:
            candidates = [local[self.key]] if self.key in local else []
            observed = _observed(store, records.get(self.key))
            if observed is not None:
                candidates.append(observed)
            return _winner(self.key, candidates)

        return self._read_from(view)

    def read(
        self, description: str, *, validate: Validator | None = None, roundtrip: bool = False
    ) -> dict[str, Any]:
        record = self._view()
        if record is None or record.deleted:
            return {}
        doc = tomlkit.parse(record.content) if roundtrip else tomllib.loads(record.content)
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
        with self.transaction():
            _ACTIVE.sessions[self.root].stage(self.key, tomlkit.dumps(doc) or "\n")

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
