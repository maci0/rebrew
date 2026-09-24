"""registry.py — declarative component registration for rebrew.

Rebrew's component registries (toolchains, decompiler backends, CLI
subcommands, GA mutations) historically lived as code literals: adding a
component meant editing host source.  This module provides the "declare,
don't hardcode" layer: each component kind can be registered from outside
the host tree and the host resolves the union at import time.

Two sources feed every registry:

1. **setuptools entry points** — an installed package declares a group
   (e.g. ``rebrew.toolchains``) and the host discovers it via
   ``importlib.metadata``.  This is the mechanism for third-party packages
   (extras, plugins) installed into the environment.
2. **data files** — a directory of declarative records (e.g. toolchain
   TOML overlays) pointed to by an environment variable.  This is the
   mechanism for project-local components that are not packaged.

The packaged built-ins remain the base registry; discovered components
merge on top.  Conflict policy (single-source discipline): a name may be
registered by exactly one source.  A duplicate raises :class:`RegistryError`
naming the incoming origin — the "no two fibers of one registry whose provisions
meet" rule of the spatiotemporal-composability model this mirrors.

Failure policy: how a broken plugin registration is handled depends on the
registry's role.  **Identity-critical** toolchains keep the loud
``RegistryError`` on a duplicate name (a wrong compiler produces wrong
bytes).  **CLI** plugin name clashes against a built-in are warn+skip
(discovery has no console yet; see ``entry_point_components``).
**Optional/tuning** registries (decompiler backends, GA mutations, flag
sets, library presets, detectors, binary loaders, cache backends,
discoverers) skip the broken or duplicate entry with a warning — a bad plugin must not brick the
importing module, matching the CLI's stub-degradation for broken command
plugins.  Tuning groups that are meant to be overridden
(``flag_sets``, ``library_presets``, ``msvc_versions``) extend/replace by
name instead of treating a second source as a conflict.
"""

from __future__ import annotations

import importlib
import logging
import sys
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

from rebrew.errors import RebrewError


class RegistryError(RebrewError, RuntimeError):
    """A plugin registration is malformed, conflicts, or fails to load.

    Structured fields (when known) let plugin authors recover without
    string-matching the message:

    - ``group`` — entry-point / registry group (e.g. ``rebrew.toolchains``)
    - ``name`` — the colliding or unloadable registration name
    - ``origin`` — where the failing registration came from
    """

    def __init__(
        self,
        message: str,
        *,
        group: str = "",
        name: str = "",
        origin: str = "",
    ) -> None:
        super().__init__(message)
        self.group = group
        self.name = name
        self.origin = origin


@dataclass(frozen=True)
class Registration:
    """One declared component: ``name = module:attr`` in group *group*."""

    name: str
    module: str
    attr: str
    group: str
    origin: str  # e.g. "entry-point" or "data-file <path>"

    @property
    def target(self) -> str:
        """``module:attr`` — the value a registration carries."""
        return f"{self.module}:{self.attr}" if self.attr else self.module


#: ``(key, entry_points())`` from the last scan; see :func:`_installed_entry_points`.
_entry_points_snapshot: tuple[tuple[Any, ...], Any] | None = None
_entry_points_lock = threading.Lock()


def _sys_path_fingerprint() -> tuple[tuple[str, int | None], ...]:
    """``(abspath, st_mtime_ns)`` per ``sys.path`` entry (``None`` if unstat-able).

    Installing, upgrading, or removing a distribution adds or removes a
    ``*.dist-info`` entry in its site directory, which bumps that directory's
    mtime.
    """
    out: list[tuple[str, int | None]] = []
    for entry in sys.path:
        path = Path(entry).absolute()
        try:
            out.append((str(path), path.stat().st_mtime_ns))
        except OSError:
            out.append((str(path), None))
    return tuple(out)


def _installed_entry_points() -> Any:
    """``entry_points()``, rescanned only when an import directory changes.

    Each ``entry_points()`` call re-reads every installed distribution's
    metadata, and one CLI start queries about ten groups.  The key includes
    the discovery function itself, so a replaced ``entry_points`` takes
    effect on the next call.
    """
    global _entry_points_snapshot
    key = (entry_points, _sys_path_fingerprint())
    snapshot = _entry_points_snapshot
    if snapshot is not None and snapshot[0] == key:
        return snapshot[1]
    with _entry_points_lock:
        snapshot = _entry_points_snapshot
        if snapshot is not None and snapshot[0] == key:
            return snapshot[1]
        eps = entry_points()
        _entry_points_snapshot = (key, eps)
        return eps


def entry_point_registrations(group: str) -> list[Registration]:
    """Every entry point declared in *group*, as registrations.

    Entry-point *values* follow the ``module`` or ``module:attr`` shape; a
    malformed value (no module) is skipped with a warning naming the group
    and name — one broken declaration must not abort discovery of the whole
    group (a bad plugin must not brick the importing module).
    """
    out: list[Registration] = []
    log = logging.getLogger(__name__)
    for ep in _installed_entry_points().select(group=group):
        module, sep, attr = ep.value.partition(":")
        if not module:
            log.warning(
                "skipping bad registration in group %r: %s = %r "
                "(expected 'module' or 'module:attr')",
                group,
                ep.name,
                ep.value,
            )
            continue
        out.append(
            Registration(
                name=ep.name,
                module=module,
                attr=attr if sep else "",
                group=group,
                origin="entry-point",
            )
        )
    return out


def import_registration(reg: Registration) -> Any:
    """Import the object a registration names (module or module:attr).

    Raises :class:`RegistryError` wrapping ANY failure, so a failing plugin is
    reported with its origin rather than a bare traceback.  ``ImportError``
    alone was too narrow: a plugin module that raises ``SyntaxError`` (or any
    other exception) at import time escaped the caller's skip/degrade policy
    and bricked the module that was importing it.
    """
    try:
        mod = importlib.import_module(reg.module)
    except Exception as exc:
        raise RegistryError(
            f"cannot load {reg.group} registration {reg.name!r} from {reg.origin}: "
            f"module {reg.module!r} not importable ({type(exc).__name__}: {exc})",
            group=reg.group,
            name=reg.name,
            origin=reg.origin,
        ) from exc
    if not reg.attr:
        return mod
    try:
        return getattr(mod, reg.attr)
    except Exception as exc:
        raise RegistryError(
            f"cannot load {reg.group} registration {reg.name!r} from {reg.origin}: "
            f"{reg.module!r} has no usable attribute {reg.attr!r} "
            f"({type(exc).__name__}: {exc})",
            group=reg.group,
            name=reg.name,
            origin=reg.origin,
        ) from exc


def load_registration_optional(reg: Registration, log: logging.Logger) -> Any | None:
    """Import a registration for an optional registry, skipping on failure.

    Optional registries (decompiler backends, GA mutations, flag sets,
    library presets, detectors, binary loaders, cache backends, discoverers)
    must not brick the importing module when a plugin is broken: the entry is
    skipped with a warning and ``None`` returned.  Toolchains use
    :func:`import_registration` directly and keep the loud
    :class:`RegistryError`.  CLI command plugins call
    :func:`import_registration` but degrade to an ``[unavailable]`` stub
    on failure (and warn+skip on duplicate names)."""
    try:
        return import_registration(reg)
    except RegistryError as exc:
        log.warning("skipping broken %s registration %r: %s", reg.group, reg.name, exc)
        return None


def iter_optional_provider_dicts(
    group: str, log: logging.Logger, *, expected: str
) -> Iterator[tuple[Registration, dict[Any, Any]]]:
    """Yield ``(reg, provided)`` for each provider function in optional *group*.

    A provider that fails to import, raises, or returns a non-dict is skipped
    with a warning; *expected* names the dict shape in that warning.  Entries
    inside *provided* are unvalidated: the caller checks each one."""
    for reg in entry_point_registrations(group):
        provider = load_registration_optional(reg, log)
        if provider is None:
            continue
        try:
            provided = provider()
        except Exception as exc:
            log.warning(
                "skipping %s provider %r: %s: %s",
                reg.group,
                reg.name,
                type(exc).__name__,
                exc,
            )
            continue
        if not isinstance(provided, dict):
            log.warning(
                "skipping %s provider %r: expected %s, got %s",
                reg.group,
                reg.name,
                expected,
                type(provided).__name__,
            )
            continue
        yield reg, provided


def merge_into(
    registry: dict[str, Any],
    name: str,
    value: Any,
    origin: str,
    *,
    group: str = "",
) -> None:
    """Insert *name* → *value* into *registry*, enforcing single-source.

    A name already present (from any earlier source, built-in or
    discovered) is a conflict: :class:`RegistryError` names the incoming origin."""
    if name in registry:
        raise RegistryError(
            f"duplicate {group or 'registry'} registration {name!r}: {origin} "
            f"conflicts with an existing registration (single-source discipline)",
            group=group,
            name=name,
            origin=origin,
        )
    registry[name] = value


def merge_provider_dict(
    registry: dict[str, Any],
    provider: Callable[[], dict[str, Any]],
    origin: str,
    *,
    group: str,
) -> None:
    """Merge every entry a provider function yields into *registry*.

    The provider returns ``{name: component}``; each name is checked for
    conflicts against everything already registered."""
    try:
        provided = provider()
    except Exception as exc:
        raise RegistryError(
            f"bad {group} provider from {origin}: {type(exc).__name__}: {exc}",
            group=group,
            origin=origin,
        ) from exc
    if not isinstance(provided, dict):
        raise RegistryError(
            f"bad {group} provider from {origin}: expected dict[str, component], "
            f"got {type(provided).__name__}",
            group=group,
            origin=origin,
        )
    for name, value in provided.items():
        merge_into(registry, name, value, origin, group=group)


def refresh_all() -> dict[str, int]:
    """Re-run discovery for every registry module and refresh its snapshot.

    Registration is import-time by default; a long-lived process (a
    dashboard, an agent harness) that installs a plugin after startup calls
    this to pick it up without a restart.  Returns ``{group: entry
    count}``, keyed by entry-point group without the ``rebrew.`` prefix
    (``toolchains``, ``binary_detectors``, ...).  CLI command groups are not
    refreshed: the umbrella app mounts them once.  Each module also exposes a single-registry ``refresh_*``
    (e.g. :func:`rebrew.toolchain.refresh_toolchain_registry`).
    """
    from rebrew import (
        binary_loader,
        compile_cache,
        decompiler,
        discover,
        metadata,
        toolchain,
        toolchain_detect,
    )
    from rebrew.matcher import compiler, mutator

    counts: dict[str, int] = {}
    counts["toolchains"] = len(toolchain.refresh_toolchain_registry())
    counts["decompiler_backends"] = len(decompiler.refresh_backends())
    counts["mutations"] = len(mutator.refresh_mutations())
    counts["flag_sets"] = len(compiler.refresh_flag_sets()[0])
    counts["library_presets"] = len(metadata.refresh_library_presets())
    toolchain_detect.refresh_detection_tables()
    counts["binary_detectors"] = len(toolchain_detect._PLUGIN_DETECTORS)
    counts["toolchain_detectors"] = len(toolchain_detect._PROFILE_COMPAT_ALL)
    counts["msvc_versions"] = len(toolchain_detect._RICH_BUILD_PROFILES_ALL) + len(
        toolchain_detect._LINKER_ERA_PROFILES_ALL
    )
    counts["binary_loaders"] = len(binary_loader.refresh_loaders())
    counts["cache_backends"] = len(compile_cache.refresh_cache_backends())
    counts["discoverers"] = len(discover.refresh_discoverers())
    return counts


__all__ = [
    "Registration",
    "RegistryError",
    "entry_point_registrations",
    "import_registration",
    "iter_optional_provider_dicts",
    "load_registration_optional",
    "merge_into",
    "merge_provider_dict",
    "refresh_all",
]
