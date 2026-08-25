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
naming both origins — the "no two fibers of one registry whose provisions
meet" rule of the spatiotemporal-composability model this mirrors.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Any


class RegistryError(RuntimeError):
    """A plugin registration is malformed, conflicts, or fails to load."""


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


def entry_point_registrations(group: str) -> list[Registration]:
    """Every entry point declared in *group*, as registrations.

    Entry-point *values* follow the ``module`` or ``module:attr`` shape; a
    malformed value (no module) raises :class:`RegistryError` naming the
    group and name, so a broken declaration is reported where it is loaded.
    """
    out: list[Registration] = []
    for ep in entry_points().select(group=group):
        module, sep, attr = ep.value.partition(":")
        if not module:
            raise RegistryError(
                f"bad registration in group {group!r}: {ep.name} = {ep.value!r} "
                "(expected 'module' or 'module:attr')"
            )
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

    Raises :class:`RegistryError` wrapping the underlying ImportError /
    AttributeError, so a failing plugin is reported with its origin rather
    than a bare traceback."""
    try:
        mod = importlib.import_module(reg.module)
    except ImportError as exc:
        raise RegistryError(
            f"cannot load {reg.group} registration {reg.name!r} from {reg.origin}: "
            f"module {reg.module!r} not importable ({exc})"
        ) from exc
    if not reg.attr:
        return mod
    try:
        return getattr(mod, reg.attr)
    except AttributeError as exc:
        raise RegistryError(
            f"cannot load {reg.group} registration {reg.name!r} from {reg.origin}: "
            f"{reg.module!r} has no attribute {reg.attr!r}"
        ) from exc


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
    discovered) is a conflict: :class:`RegistryError` names both origins."""
    if name in registry:
        raise RegistryError(
            f"duplicate {group or 'registry'} registration {name!r}: {origin} "
            f"conflicts with an existing registration (single-source discipline)"
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
            f"bad {group} provider from {origin}: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(provided, dict):
        raise RegistryError(
            f"bad {group} provider from {origin}: expected dict[str, component], "
            f"got {type(provided).__name__}"
        )
    for name, value in provided.items():
        merge_into(registry, name, value, origin, group=group)
