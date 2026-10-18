"""Discovery and ownership-preserving edits for metadata TOML drop-in directories."""

import contextlib
import copy
import hashlib
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import tomlkit
from tomlkit import TOMLDocument

from rebrew.metadata.locking import file_transaction, project_transaction
from rebrew.utils import (
    atomic_write_bytes,
    atomic_write_locked,
    load_toml_for_write_strict,
    load_tomllib,
)


def metadata_paths(path: Path) -> tuple[Path, ...]:
    """Return the optional main TOML followed by direct, sorted ``.d/*.toml`` files."""
    try:
        path.stat()
    except FileNotFoundError:
        paths = []
    else:
        paths = [path]
    try:
        members = list(path.with_suffix(".d").iterdir())
    except FileNotFoundError:
        members = []
    paths.extend(sorted(p for p in members if p.suffix == ".toml" and p.is_file()))
    return tuple(paths)


def metadata_fingerprint(path: Path) -> tuple[tuple[str, int, int, int, int], ...]:
    """Identify all input files, including additions, removals and atomic replacements.

    Stats each input exactly once: the main file, then every direct `.d/*.toml`.
    ``metadata_paths`` would stat the main file again and stat every fragment
    once just to answer ``is_file``, and this runs on every cached metadata read.
    """
    result: list[tuple[str, int, int, int, int]] = []
    try:
        stat = path.stat()
    except FileNotFoundError:
        pass
    else:
        result.append((str(path), stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, stat.st_ino))
    try:
        with os.scandir(path.with_suffix(".d")) as entries:
            members = sorted(
                (entry for entry in entries if entry.name.endswith(".toml") and entry.is_file()),
                key=lambda entry: entry.name,
            )
            for entry in members:
                try:
                    stat = entry.stat()
                except FileNotFoundError:
                    continue
                result.append(
                    (entry.path, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, stat.st_ino)
                )
    except FileNotFoundError:
        pass
    return tuple(result)


def metadata_bytes(path: Path) -> bytes | None:
    """Snapshot a store; preserve the original byte digest for a single main file."""
    paths = metadata_paths(path)
    if not paths:
        return None
    if paths == (path,):
        return path.read_bytes()
    chunks = [b"rebrew metadata collection\0"]
    for member in paths:
        name, content = member.relative_to(path.parent).as_posix().encode(), member.read_bytes()
        for part in (name, content):
            chunks.extend((str(len(part)).encode(), b":", part))
    return b"".join(chunks)


def metadata_digest(path: Path) -> str | None:
    """Hash every file and its name; ``None`` means the whole store is absent."""
    content = metadata_bytes(path)
    return hashlib.sha256(content).hexdigest() if content is not None else None


def _records(doc: Any, path: Path) -> Iterator[tuple[tuple[str, ...], Any]]:
    """Walk record boundaries, keeping shared schema containers separate from records."""
    depths = {
        "rebrew-source.toml": {"definitions": 4, "files": 3},
        "rebrew-types.toml": {"types": 3},
    }.get(path.name, {})

    def walk(
        value: Any, keys: tuple[str, ...], depth: int
    ) -> Iterator[tuple[tuple[str, ...], Any]]:
        if len(keys) == depth:
            yield keys, value
        else:
            for key, child in value.items():
                yield from walk(child, (*keys, key), depth)

    for key, value in doc.items():
        if key == "source" and path.name == "rebrew-functions.toml":
            for kind, records in value.items():
                yield from walk(records, (key, kind), 5 if kind == "definitions" else 4)
        elif key != "format":
            yield from walk(value, (key,), depths.get(key, 1))


def _set_record(doc: Any, keys: tuple[str, ...], value: Any) -> None:
    if keys[0] == "source":
        source = doc.setdefault("source", {})
        source.setdefault("definitions", {})
        source.setdefault("files", {})
    for key in keys[:-1]:
        doc = doc.setdefault(key, tomlkit.table() if isinstance(doc, TOMLDocument) else {})
    doc[keys[-1]] = copy.deepcopy(value)


def _delete_record(doc: Any, keys: tuple[str, ...]) -> None:
    parent = doc
    for key in keys[:-1]:
        parent = parent[key]
    del parent[keys[-1]]
    # Keep required schema containers, but remove empty identity containers.
    for size in range(len(keys) - 1, 2 if keys[0] == "source" else 1, -1):
        parent = doc
        for key in keys[: size - 1]:
            parent = parent[key]
        if not parent[keys[size - 1]]:
            del parent[keys[size - 1]]


def load_metadata_collection(
    path: Path,
    description: str,
    *,
    validate: Callable[[Any], Any] | None = None,
    roundtrip: bool = True,
) -> dict[str, Any]:
    """Merge validated records, refusing duplicates rather than hiding durable state."""
    paths = metadata_paths(path)

    def load(member: Path) -> dict[str, Any]:
        return (
            load_toml_for_write_strict(member, description) if roundtrip else load_tomllib(member)
        )

    if len(paths) == 1:
        doc = load(paths[0])
        if validate is not None:
            validate(doc)
        return doc
    merged: dict[str, Any] = tomlkit.document() if roundtrip else {}
    owners: dict[tuple[str, ...], Path] = {}
    for member in paths:
        doc = load(member)
        if validate is not None:
            validate(doc)
        for container in ("definitions", "files", "types"):
            if container in doc and container not in merged:
                merged[container] = tomlkit.table()
        if "source" in doc:
            merged.setdefault("source", {"definitions": {}, "files": {}})
        if "format" in doc:
            if "format" in merged and merged["format"] != doc["format"]:
                raise ValueError(f"{member}: inconsistent metadata format")
            merged["format"] = doc["format"]
        for keys, value in _records(doc, path):
            if keys in owners:
                raise ValueError(
                    f"duplicate metadata record {keys!r} in {owners[keys]} and {member}"
                )
            owners[keys] = member
            _set_record(merged, keys, value)
    return merged


def write_metadata_collection(path: Path, doc: dict[str, Any], description: str) -> None:
    """Write under the caller's store lock, retaining each existing record's owner."""
    paths = metadata_paths(path)
    if not any(member != path for member in paths):
        atomic_write_locked(path, tomlkit.dumps(doc))
        return
    # Load and prepare every file before writing any, so malformed input never
    # causes a partially applied edit. Writers share the main store's lock.
    # Only a member this edit changes is copied and rendered: a store with many
    # fragments must not pay a parse and a dump for every one of them.
    before = {member: member.read_bytes() for member in paths}
    originals = {member: load_toml_for_write_strict(member, description) for member in paths}
    owners: dict[tuple[str, ...], Path] = {}
    original_records: dict[tuple[str, ...], Any] = {}
    for member, original in originals.items():
        for keys, value in _records(original, path):
            if keys in owners:
                raise ValueError(
                    f"duplicate metadata record {keys!r} in {owners[keys]} and {member}"
                )
            owners[keys] = member
            original_records[keys] = value
    updated = dict(originals)
    copied: set[Path] = set()
    touched: set[Path] = set()

    def writable(member: Path) -> Any:
        value = updated[member]
        if member not in copied:
            value = copy.deepcopy(value)
            updated[member] = value
            copied.add(member)
        return value

    remaining = dict(_records(doc, path))
    for keys, member in owners.items():
        if keys not in remaining:
            _delete_record(writable(member), keys)
            touched.add(member)
    for keys, value in remaining.items():
        if keys in original_records and original_records[keys] == value:
            continue
        member = owners.get(keys, path)
        if member not in updated:
            updated[member] = tomlkit.document()
            copied.add(member)
            if "format" in doc:
                updated[member]["format"] = doc["format"]
            for container in ("definitions", "files", "types"):
                if container in doc:
                    updated[member][container] = tomlkit.table()
        _set_record(writable(member), keys, value)
        touched.add(member)
    for member, value in updated.items():
        if "format" in doc and value.get("format") != doc["format"]:
            writable(member)["format"] = doc["format"]
            touched.add(member)
        if "source" in value:
            for container in ("definitions", "files"):
                if not value["source"].get(container):
                    writable(member)["source"][container] = tomlkit.table()
                    touched.add(member)
        for container in ("definitions", "files", "types"):
            if container in doc and not value.get(container):
                updated[member] = writable(member)
                updated[member][container] = tomlkit.table()
                touched.add(member)
    rendered = []
    for member, value in updated.items():
        if member not in touched:
            continue
        content = tomlkit.dumps(value)
        if member in originals and content == tomlkit.dumps(originals[member]):
            continue
        rendered.append((member, content))
    written = []
    try:
        for member, content in rendered:
            written.append(member)
            atomic_write_locked(member, content)
    except BaseException:
        for member in reversed(written):
            if member in before:
                atomic_write_bytes(member, before[member], mode=0o444)
            else:
                member.unlink(missing_ok=True)
        raise


def project_metadata_paths(directory: Path) -> tuple[Path, ...]:
    """List project metadata inputs for review guards and live coverage caches."""
    paths = set(directory.glob("rebrew-*.toml"))
    for dropins in directory.glob("rebrew-*.d"):
        if dropins.is_dir():
            paths.update(metadata_paths(dropins.with_suffix(".toml")))
    return tuple(sorted(path for path in paths if path.is_file()))


class TomlStore:
    """Managed TOML document with optional ownership-preserving drop-ins."""

    name = "toml"

    def __init__(self, path: Path, root: Path) -> None:
        self.path = path
        self.root = root
        self.location = path

    def read(
        self,
        description: str,
        *,
        validate: Callable[[Any], Any] | None = None,
        roundtrip: bool = False,
    ) -> dict[str, Any]:
        """Read the current document, validating every fragment and the combined view."""
        doc = load_metadata_collection(
            self.path, description, validate=validate, roundtrip=roundtrip
        )
        if validate is not None and len(metadata_paths(self.path)) > 1:
            validate(doc)
        return doc

    def write(self, doc: dict[str, Any], description: str) -> None:
        """Publish a document under the collection transaction."""
        with self.transaction():
            write_metadata_collection(self.path, doc, description)

    def exists(self) -> bool:
        """Whether any member of this store exists."""
        return bool(metadata_paths(self.path))

    def documents(self, *, recursive: bool = False) -> tuple[Path, ...]:
        """Discover logical TOML collections, excluding caches and nested projects."""
        names = {
            "rebrew-functions.toml",
            "rebrew-data.toml",
            "rebrew-types.toml",
            "rebrew-libraries.toml",
        }
        if not recursive:
            return tuple(
                path for path in project_metadata_paths(self.path.parent) if path.name in names
            )
        paths = set()
        for directory, folders, files in os.walk(self.path.parent):
            parent = Path(directory)
            if parent != self.path.parent and "rebrew-project.toml" in files:
                folders[:] = []
                continue
            for name in files:
                if name in names:
                    paths.add(parent / name)
            for name in folders:
                candidate = Path(name).with_suffix(".toml")
                if name.endswith(".d") and candidate.name in names:
                    path = parent / candidate
                    if metadata_paths(path):
                        paths.add(path)
            folders[:] = [
                name
                for name in folders
                if not name.startswith(".")
                and name not in {"node_modules", "__pycache__"}
                and Path(name).with_suffix(".toml").name not in names
            ]
        return tuple(sorted(paths))

    def inputs(self) -> tuple[Path, ...]:
        """Files and discovery locations to watch for changes."""
        return tuple(
            dict.fromkeys((self.path, self.path.with_suffix(".d"), *metadata_paths(self.path)))
        )

    def fingerprint(self) -> tuple[tuple[str, int, int, int, int], ...]:
        """Stat every input without parsing its contents."""
        return metadata_fingerprint(self.path)

    def snapshot(self) -> bytes | None:
        """Take the complete input snapshot used by reviewed edits."""
        return metadata_bytes(self.path)

    def digest(self) -> str | None:
        """Hash the complete input snapshot."""
        return metadata_digest(self.path)

    @contextlib.contextmanager
    def transaction(self) -> Iterator[None]:
        """Serialize a read/modify/write, reentrantly across threads and processes."""
        with (
            project_transaction(self.root, self.path.name),
            file_transaction(self.path.parent, self.path.name),
        ):
            yield

    def remove(self) -> None:
        """Remove every fragment under the store transaction."""
        with self.transaction():
            before = {member: member.read_bytes() for member in metadata_paths(self.path)}
            removed = []
            try:
                for member in before:
                    member.unlink(missing_ok=True)
                    removed.append(member)
            except BaseException:
                for member in removed:
                    atomic_write_bytes(member, before[member], mode=0o444)
                raise
