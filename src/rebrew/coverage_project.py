"""Live coverage views derived from project inputs, without snapshot files.

The catalog and portable exporter share normalization and immutable snapshot
construction. This reader never compiles, changes metadata or writes exports.
Unchanged inputs reuse the same view; a failed target does not hide healthy ones.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
lazy import hashlib
lazy import time
lazy from datetime import UTC, datetime
lazy from pathlib import Path
lazy from types import MappingProxyType

from rebrew.config import ProjectConfig, inventory_path_for, load_config, target_module
from rebrew.coverage_toml import (
    CoverageSnapshot,
    coverage_document,
    previous_measurements,
    snapshot_from_document,
)
from rebrew.errors import RebrewError
lazy from rebrew.catalog.pipeline import build_catalog_data
lazy from rebrew.coverage_db import import_verify_rows
lazy from rebrew.data_ownership import ownership_inputs
lazy from rebrew.formats.binary_loader import load_binary
lazy from rebrew.metadata.functions import load_status_history
lazy from rebrew.metadata.storage import metadata_inputs, metadata_store
lazy from rebrew.sources import scan_files
lazy from rebrew.verify_cache import CACHE_FILENAME, cache_path_for
lazy from rebrew.workspace import read_config, targets_table

__all__ = ["ProjectCoverageError", "ProjectCoverageView", "load_project_coverage"]


class ProjectCoverageError(RebrewError):
    """Project inputs cannot produce a coherent coverage view."""


@dataclass(frozen=True)
class ProjectCoverageView:
    """One coherent view, including per-target failures and change tokens."""

    snapshots: Mapping[str, CoverageSnapshot]
    failures: Mapping[str, str]
    versions: tuple[tuple[str, str, int], ...]
    input_stats: tuple[tuple[str, int, int], ...]


@dataclass
class _Target:
    fingerprint: tuple[tuple[str, int, int, int, int], ...]
    baseline: dict[str, Any]
    snapshot: CoverageSnapshot


@dataclass
class _Project:
    config_key: tuple[int, int, int, int]
    configs: dict[str, ProjectConfig]
    targets: dict[str, _Target] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)
    view: ProjectCoverageView | None = None
    checked_at: float = 0.0
    lock: Any = field(default_factory=threading.RLock)


_PROJECTS: OrderedDict[Path, _Project] = OrderedDict()
_LOCK = threading.RLock()
_MAX_PROJECTS = 4
# A bounded polling delay amortizes source-tree stats across concurrent requests.
_POLL_INTERVAL = 0.25


def _stat(path: Path) -> tuple[int, int, int, int]:
    try:
        st = path.stat()
    except FileNotFoundError:
        return (0, 0, 0, 0)
    return st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_ino


def _inputs(
    cfg: ProjectConfig, scans: dict[Path, tuple[Path, ...]] | None = None
) -> tuple[tuple[str, int, int, int, int], ...]:
    def _scan(root: Path) -> tuple[Path, ...]:
        root = root.resolve()
        if scans is None:
            return tuple(scan_files(root))
        if root not in scans:
            scans[root] = tuple(scan_files(root))
        return scans[root]

    paths = {
        cfg.root / "rebrew-project.toml",
        cfg.target_binary,
        inventory_path_for(cfg.reversed_dir, cfg),
        cache_path_for(cfg),
        # A matching legacy cache can be read before the first isolated write.
        cfg.root / ".rebrew" / CACHE_FILENAME,
    }
    paths.update(metadata_inputs(cfg.metadata_dir))
    paths.update(ownership_inputs(cfg))
    roots = {cfg.reversed_dir}
    if cfg.shared_dir is not None:
        roots.add(cfg.shared_dir)
    for external in (cfg.compiler_includes, cfg.compiler_libs):
        if external != Path() and external.is_dir() and external.resolve() != cfg.root:
            paths.update(_scan(external))
    for root in roots:
        paths.update(_scan(root))
        for parent in (root, *root.parents):
            library = parent / "rebrew-libraries.toml"
            paths.add(library)
            paths.update(metadata_store(library).inputs())
    if cfg.raw_link is not None:
        paths.update((cfg.raw_link, cfg.raw_link.with_suffix(".map")))
    return tuple((str(path), *_stat(path)) for path in sorted(paths))


def _configs(root: Path) -> tuple[dict[str, ProjectConfig], dict[str, str]]:
    configs: dict[str, ProjectConfig] = {}
    failures: dict[str, str] = {}
    targets = targets_table(read_config(root))
    if not targets:
        raise ProjectCoverageError(f"{root}: no configured targets")
    for target in targets:
        try:
            configs[target] = load_config(root, target=target)
        except (OSError, ValueError, KeyError, TypeError, RebrewError) as exc:
            failures[target] = str(exc)
    return configs, failures


def _target_view(cfg: ProjectConfig, old: _Target | None) -> _Target:
    # Never publish a frame assembled across an input change. One retry covers
    # an ordinary atomic metadata replacement; a busy writer stays explicit.
    for _attempt in range(2):
        before = _inputs(cfg)
        cfg = load_config(cfg.root, target=cfg.target_name)
        if not cfg.target_binary.is_file():
            raise ProjectCoverageError(
                f"{cfg.target_name}: target binary missing: {cfg.target_binary}"
            )
        load_binary(cfg.target_binary)
        data = build_catalog_data(cfg, progress=False)["data"]
        previous = old.baseline if old is not None else {}
        rows = import_verify_rows(
            cfg.root,
            cfg.target_name,
            previous_measurements(previous),
            datetime.now(UTC).isoformat(),
        )
        document = coverage_document(
            cfg.target_name,
            data,
            verify_rows=rows,
            history=load_status_history(cfg.metadata_dir, target_module(cfg)),
        )
        snapshot = snapshot_from_document(
            cfg.root / "rebrew-project.toml", document, cfg.target_name
        )
        after = _inputs(cfg)
        if before == after:
            baseline = {
                "version": document["version"],
                "verify_results": document["verify_results"],
            }
            return _Target(after, baseline, snapshot)
    raise ProjectCoverageError(f"{cfg.target_name}: inputs changed while coverage was being read")


def load_project_coverage(root: Path, *, refresh: bool = False) -> ProjectCoverageView:
    """Read live project coverage; changes are detected within 250 milliseconds.

    ``refresh`` bypasses the polling delay. Failed targets are retried on each
    poll, without replacing successful siblings with a stale whole-project export.
    The view remains immutable and is reused by identity when nothing changed.
    """
    root = root.resolve()
    with _LOCK:
        state = _PROJECTS.get(root)
        if state is None:
            state = _Project((0, 0, 0, 0), {})
            _PROJECTS[root] = state
        _PROJECTS.move_to_end(root)
        while len(_PROJECTS) > _MAX_PROJECTS:
            _PROJECTS.popitem(last=False)
    with state.lock:
        stamp = time.monotonic()
        if state is not None and not refresh and stamp - state.checked_at < _POLL_INTERVAL:
            assert state.view is not None
            return state.view
        try:
            key = _stat(root / "rebrew-project.toml")
            if key == (0, 0, 0, 0):
                raise ProjectCoverageError(f"{root}: no rebrew-project.toml")
            if state.config_key != key:
                configs, failures = _configs(root)
                state.config_key = key
                state.configs = configs
                state.targets.clear()
                state.failures = failures
                state.view = None
        except (OSError, ValueError, KeyError, TypeError, RebrewError) as exc:
            raise ProjectCoverageError(f"{root}: cannot read project coverage: {exc}") from exc
        changed = state.view is None
        failures = dict(state.failures)
        scans: dict[Path, tuple[Path, ...]] = {}
        for target in sorted(state.configs.keys() | state.failures.keys()):
            cfg = state.configs.get(target)
            old = state.targets.get(target)
            try:
                fingerprint = _inputs(cfg, scans) if cfg is not None else None
                if old is not None and old.fingerprint == fingerprint:
                    failures.pop(target, None)
                    continue
                if cfg is None:
                    cfg = load_config(root, target=target)
                state.configs[target] = cfg
                current = _target_view(cfg, old)
                state.targets[target] = current
                failures.pop(target, None)
                changed = True
            except (OSError, ValueError, KeyError, TypeError, RebrewError) as exc:
                if target in state.targets or failures.get(target) != str(exc):
                    changed = True
                state.targets.pop(target, None)
                failures[target] = str(exc)
        # A shared input can change after an earlier target finished. Validate
        # the complete project frame before publishing any successful target.
        if changed:
            final_scans: dict[Path, tuple[Path, ...]] = {}
            for target, item in list(state.targets.items()):
                try:
                    if item.fingerprint == _inputs(state.configs[target], final_scans):
                        continue
                    reason = f"{target}: inputs changed while project coverage was being read"
                except (OSError, ValueError, KeyError, TypeError, RebrewError) as exc:
                    reason = str(exc)
                state.targets.pop(target)
                failures[target] = reason
                changed = True
        if failures != state.failures:
            changed = True
        state.failures = failures
        if _stat(root / "rebrew-project.toml") != state.config_key:
            state.config_key = (0, 0, 0, 0)
            raise ProjectCoverageError(
                f"{root}: configuration changed while coverage was being read"
            )
        if changed:
            versions = tuple(
                (
                    f"project:{target}",
                    hashlib.sha256(repr(item.fingerprint).encode()).hexdigest(),
                    sum(row[3] for row in item.fingerprint),
                )
                for target, item in sorted(state.targets.items())
            ) + tuple(
                (
                    f"project:{target}",
                    hashlib.sha256(f"{state.config_key!r}:{reason}".encode()).hexdigest(),
                    0,
                )
                for target, reason in sorted(failures.items())
            )
            state.view = ProjectCoverageView(
                MappingProxyType({target: item.snapshot for target, item in state.targets.items()}),
                MappingProxyType(dict(failures)),
                versions,
                tuple(
                    sorted(
                        {
                            (path, mtime, size)
                            for item in state.targets.values()
                            for path, mtime, _ctime, size, _ino in item.fingerprint
                        }
                    )
                ),
            )
        state.checked_at = time.monotonic()
        assert state.view is not None
        return state.view
