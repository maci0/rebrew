"""Coordinated metadata and source-file edits with failure rollback."""

from contextlib import ExitStack, contextmanager
lazy import hashlib
lazy import json
lazy import logging
lazy import os
lazy import tempfile
lazy from collections.abc import Callable, Iterator
lazy from pathlib import Path

lazy from rebrew.metadata.locking import file_transaction
lazy from rebrew.metadata.storage import (
    managed_metadata_filenames,
    metadata_store,
    toml_fragment_paths,
)
lazy from rebrew.utils import atomic_write_bytes, path_identity


def path_identity_digest(path: Path) -> str:
    """Pin the spelling and every symlink traversed while resolving an input."""
    return json.dumps(path_identity(path), sort_keys=True)


def coordinated_inputs(
    directory: Path,
    sources: list[Path],
    *,
    watched: list[Path] | None = None,
    discovery_roots: list[Path] | None = None,
) -> dict[str, str | None]:
    """Hash selected and read-only inputs, source discovery sets, and metadata."""
    directory = directory.resolve()
    result: dict[str, str | None] = {}
    for path in sorted({p.absolute() for p in [*sources, *(watched or [])]}):
        result["path-identity:" + str(path)] = path_identity_digest(path)
    for path in sorted({p.resolve() for p in [*sources, *(watched or [])]}):
        result[str(path)] = (
            metadata_store(path).digest()
            if path.name in managed_metadata_filenames()
            else hashlib.sha256(path.read_bytes()).hexdigest()
            if path.is_file()
            else None
        )
    for path in sorted({p.resolve() for p in sources}):
        result["source-mode:" + str(path)] = (
            oct(path.stat().st_mode & 0o777) if path.is_file() else None
        )
    for root in sorted({p.resolve() for p in discovery_roots or []}):
        if not root.is_dir():
            raise ValueError(f"source discovery root is missing: {root}")
        names = sorted(
            str(p.relative_to(root))
            for p in root.rglob("*")
            if p.is_file() and p.suffix.lower() in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}
        )
        result["discovery:" + str(root)] = hashlib.sha256(json.dumps(names).encode()).hexdigest()
    for name in sorted(managed_metadata_filenames()):
        store = metadata_store(directory / name)
        result[str(directory / name)] = store.digest()
    config = metadata_store(directory / "rebrew-functions.toml").root / "rebrew-project.toml"
    result["path-identity:" + str(config.absolute())] = path_identity_digest(config)
    result[str(config)] = (
        hashlib.sha256(config.read_bytes()).hexdigest() if config.is_file() else None
    )
    return result


class CoordinatedStage(dict[Path, Path]):
    """Staged originals and exclusively published source outputs."""

    def __init__(self, stage_paths: list[Path]) -> None:
        super().__init__()
        self.stage_paths = set(stage_paths)
        self.published: dict[Path, tuple[int, int, str, int]] = {}

    def publish(self, path: Path, content: bytes, *, mode: int | None = None) -> None:
        """Publish without replacing a file created by another writer."""
        path = path.absolute()
        if path not in self.stage_paths or path in self.published:
            raise ValueError(f"source output was not uniquely selected for publication: {path}")
        if mode is None:
            mode = self[path].stat().st_mode & 0o777 if path in self else 0o644
        fd, temporary = tempfile.mkstemp(prefix=".rebrew-publish-", dir=path.parent)
        temp = Path(temporary)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(content)
                output.flush()
                os.fchmod(output.fileno(), mode)
                os.fsync(output.fileno())
            os.link(temp, path)
            stat = path.lstat()
            self.published[path] = (
                stat.st_dev,
                stat.st_ino,
                hashlib.sha256(content).hexdigest(),
                stat.st_mode & 0o777,
            )
        finally:
            temp.unlink(missing_ok=True)

    def is_unchanged_publication(self, path: Path) -> bool:
        """True only when the path still contains the inode and bytes we published."""
        expected = self.published.get(path)
        if expected is None or path.is_symlink() or not path.is_file():
            return False
        stat = path.stat()
        return (
            stat.st_dev,
            stat.st_ino,
            hashlib.sha256(path.read_bytes()).hexdigest(),
            stat.st_mode & 0o777,
        ) == expected


@contextmanager
def coordinated_transaction(
    directory: Path,
    sources: list[Path],
    *,
    expected_inputs: dict[str, str | None],
    stage: list[Path] | None = None,
    watched: list[Path] | None = None,
    discovery_roots: list[Path] | None = None,
    validate: Callable[[], None] | None = None,
    validate_after: Callable[[], None] | None = None,
) -> Iterator[CoordinatedStage]:
    """Lock stores, stage existing sources and restore all inputs on exceptions.

    Sources must be explicitly selected inside the project; include the output
    path even when absent. ``stage`` selects which reviewed sources are moved
    aside (defaults to all). ``watched`` hashes additional read-only files;
    ``discovery_roots`` also fingerprints discovered C/C++ path names. The
    caller publishes outputs using the yielded mapping's ``publish`` method;
    staged originals remain available through its original-to-backup mapping.
    Metadata writes must use their normal owner APIs. SQL backends use a shared
    transaction; TOML fragments are journaled byte-for-byte while the store locks
    are held. This is exception rollback, not a crash recovery journal.
    """
    directory = directory.resolve()
    if any(".." in p.parts for p in sources):
        raise ValueError("source paths must not contain parent traversal")
    paths = sorted({p.absolute() for p in sources})
    stage_paths = sorted({p.absolute() for p in (stage if stage is not None else sources)})
    if not set(stage_paths) <= set(paths):
        raise ValueError("staged files must be included in selected source inputs")
    base = [directory / name for name in sorted(managed_metadata_filenames())]
    project_root = metadata_store(base[0]).root
    store_paths = sorted(
        {
            *base,
            *(
                p.resolve()
                for p in watched or []
                if p.name in managed_metadata_filenames()
                and p.resolve().is_relative_to(project_root)
            ),
        }
    )
    stores = [metadata_store(path) for path in store_paths]
    for path in paths:
        if path.suffix.lower() not in {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"}:
            raise ValueError(f"only C/C++ source files can be staged: {path}")
        if path.is_symlink() or not path.resolve().is_relative_to(project_root):
            raise ValueError(f"source must be a non-symlink inside the project: {path}")
        if path.exists() and not path.is_file():
            raise ValueError(f"source is not a regular file: {path}")
    if any(store.name != stores[0].name for store in stores) or stores[0].name not in {
        "toml",
        "sqlite",
        "pgsql",
    }:
        raise ValueError("coordinated edits require one supported metadata backend")
    if not (project_root / "rebrew-project.toml").is_file():
        raise ValueError("coordinated edits require a project configuration")
    staged = CoordinatedStage(stage_paths)
    absent: set[Path] = set()
    original: dict[Path, tuple[bytes, int]] = {}
    snapshotted = False
    # Keep the project lock until after database commit or source restoration.
    with file_transaction(project_root, "rebrew-project.toml"):
        current_stores = [metadata_store(path) for path in store_paths]
        if any(
            a.name != b.name or a.root != b.root
            for a, b in zip(stores, current_stores, strict=True)
        ):
            raise ValueError("metadata backend changed; review a new plan")
        try:
            with ExitStack() as locks:
                for store in stores:
                    locks.enter_context(store.transaction())
                if (
                    coordinated_inputs(
                        directory, paths, watched=watched, discovery_roots=discovery_roots
                    )
                    != expected_inputs
                ):
                    raise ValueError("coordinated inputs changed; review a new plan")
                if validate is not None:
                    validate()
                if stores[0].name == "toml":
                    for store in stores:
                        for path in toml_fragment_paths(store):
                            if path.is_symlink():
                                raise ValueError(f"metadata fragment is a symlink: {path}")
                            original[path] = (path.read_bytes(), path.stat().st_mode & 0o777)
                snapshotted = True
                for path in stage_paths:
                    key = str(path.resolve())
                    expected = expected_inputs.get(key)
                    expected_mode = expected_inputs.get("source-mode:" + key)
                    if expected is None:
                        if path.exists() or path.is_symlink():
                            raise FileExistsError(
                                f"unreviewed source appeared during staging: {path}"
                            )
                        absent.add(path)
                        continue
                    if path.is_symlink() or not path.is_file():
                        raise ValueError(f"source changed or disappeared during staging: {path}")
                    fd, name = tempfile.mkstemp(prefix=".rebrew-stage-", dir=path.parent)
                    os.close(fd)
                    backup = Path(name)
                    try:
                        os.replace(path, backup)
                    except BaseException:
                        backup.unlink(missing_ok=True)
                        raise
                    staged[path] = backup
                    if (
                        backup.is_symlink()
                        or not backup.is_file()
                        or hashlib.sha256(backup.read_bytes()).hexdigest() != expected
                        or oct(backup.stat().st_mode & 0o777) != expected_mode
                    ):
                        raise ValueError(f"source changed during staging; edit preserved: {path}")
                for path in stage_paths:
                    if path.exists() or path.is_symlink():
                        raise FileExistsError(
                            f"source reappeared during staging; edit preserved: {path}"
                        )
                yield staged
                if validate_after is not None:
                    validate_after()
                for path, backup in staged.items():
                    key = str(path.resolve())
                    if (
                        backup.is_symlink()
                        or not backup.is_file()
                        or hashlib.sha256(backup.read_bytes()).hexdigest()
                        != expected_inputs.get(key)
                        or oct(backup.stat().st_mode & 0o777)
                        != expected_inputs.get("source-mode:" + key)
                    ):
                        raise ValueError(f"staged original changed during edit: {path}")
                for path in stage_paths:
                    if path in staged.published:
                        if not staged.is_unchanged_publication(path):
                            raise ValueError(
                                f"published source changed during edit; edit preserved: {path}"
                            )
                    elif path.exists() or path.is_symlink():
                        raise FileExistsError(
                            f"source reappeared during edit; edit preserved: {path}"
                        )
                for path in set(paths) - set(stage_paths):
                    key = str(path.resolve())
                    digest = (
                        hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
                    )
                    source_mode = oct(path.stat().st_mode & 0o777) if path.is_file() else None
                    if digest != expected_inputs.get(key) or source_mode != expected_inputs.get(
                        "source-mode:" + key
                    ):
                        raise ValueError(f"read-only source changed during edit: {path}")
        except BaseException as original_error:
            failures: list[BaseException] = []
            if stores[0].name == "toml" and snapshotted:
                current = {path for store in stores for path in toml_fragment_paths(store)}
                for path in current - original.keys():
                    try:
                        path.unlink()
                    except OSError as exc:
                        failures.append(exc)
                for path, (content, mode) in original.items():
                    try:
                        atomic_write_bytes(path, content, mode=mode)
                    except OSError as exc:
                        failures.append(exc)
            for path in stage_paths:
                try:
                    if path.exists() or path.is_symlink():
                        if staged.is_unchanged_publication(path):
                            path.unlink()
                        else:
                            if path in staged:
                                failures.append(
                                    FileExistsError(
                                        f"concurrent file preserved at {path}; staged original retained at {staged[path]}"
                                    )
                                )
                            continue
                    if path in staged:
                        os.link(staged[path], path, follow_symlinks=False)
                        staged[path].unlink()
                except OSError as exc:
                    failures.append(exc)
            if failures:
                raise BaseExceptionGroup(
                    "coordinated edit and rollback failed", [original_error, *failures]
                ) from original_error
            raise
        else:
            for backup in staged.values():
                try:
                    backup.unlink(missing_ok=True)
                except OSError:
                    logging.getLogger(__name__).warning("could not remove staged backup %s", backup)
