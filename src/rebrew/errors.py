"""errors.py — the common base of every error rebrew raises at library callers.

Rebrew's error types carry structured fields (``kind``, ``name``,
``retryable``, ``status_code``) so a consumer branches on data instead of
matching message substrings.  What they lacked was a single base: embedding
code had to enumerate ``ToolchainError``, ``RecompileError``, ``McpError``,
``RegistryError`` and the rest in every ``except`` clause, and a rebrew
release that added a new error type escaped those handlers silently.

:class:`RebrewError` is that base.  Every public error type below inherits it
*in addition to* its original base, so ``except RuntimeError`` /
``except ValueError`` in existing consumer code keeps working unchanged:

    from rebrew.errors import RebrewError

    try:
        result = compile_and_compare(cfg, path, symbol, target, cflags)
    except RebrewError as exc:
        if exc.retryable:
            ...

This module is the single import point for those types: every public
subclass is re-exported here (``from rebrew.errors import DosboxError``), so a
consumer never has to know which submodule defines which error.  The classes
load on first attribute access, keeping ``import rebrew.errors`` free of the
compile stack.

``retryable`` is the one field the base carries, because "may I try this
again?" is the question every caller asks and the answer must not depend on
which subclass arrived.  It defaults to ``False`` (not retryable); the
subclasses that can tell transient from permanent (``ToolchainError``,
``RecompileError``, ``McpError``) set it per instance.  Domain fields
(``kind``, ``name``, ``status_code``, ``group``) stay on the subclass that
can actually fill them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Same names ``__getattr__`` loads at runtime.  Present here so a type
# checker sees ``from rebrew.errors import ConfigError`` as that class.
if TYPE_CHECKING:
    from rebrew.coff_reloc import CatalogScanError as CatalogScanError
    from rebrew.coff_reloc import UnresolvedSymbolError as UnresolvedSymbolError
    from rebrew.config import ConfigError as ConfigError
    from rebrew.config import ConfigKeyError as ConfigKeyError
    from rebrew.config import ConfigNotFoundError as ConfigNotFoundError
    from rebrew.decompme import DecompmeError as DecompmeError
    from rebrew.delphi16 import Delphi16Error as Delphi16Error
    from rebrew.dosbox import DosboxError as DosboxError
    from rebrew.ghidra.client import McpApplyAborted as McpApplyAborted
    from rebrew.ghidra.client import McpError as McpError
    from rebrew.lzexe import NotLzexeError as NotLzexeError
    from rebrew.metadata import LibraryOverrideError as LibraryOverrideError
    from rebrew.metadata_model import MetadataValidationError as MetadataValidationError
    from rebrew.msvc16 import Msvc16Error as Msvc16Error
    from rebrew.ne_loader import NeParseError as NeParseError
    from rebrew.omf16 import Omf16Error as Omf16Error
    from rebrew.orphans import OrphanInventoryError as OrphanInventoryError
    from rebrew.plugin import ComponentError as ComponentError
    from rebrew.recompile_client import RecompileError as RecompileError
    from rebrew.registry import RegistryError as RegistryError
    from rebrew.struct_recover import NoDecompilationError as NoDecompilationError
    from rebrew.tc16 import Tc16Error as Tc16Error
    from rebrew.toolchain import ToolchainError as ToolchainError
    from rebrew.workspace.config import WorkspaceNotFound as WorkspaceNotFound


class RebrewError(Exception):
    """Base of every error rebrew raises across its public modules.

    Subclasses keep their original base (``RuntimeError`` / ``ValueError``)
    so pre-existing ``except`` clauses are unaffected; this adds the umbrella
    a consumer needs to catch "rebrew failed" without enumerating types.
    """

    #: Whether retrying the same call can succeed.  Conservative default —
    #: a subclass that cannot distinguish transient from permanent leaves it
    #: ``False`` rather than inviting a retry loop that cannot terminate.
    retryable: bool = False


#: Every public error class in the package, keyed by the name a consumer
#: imports from ``rebrew.errors``.  A new ``RebrewError`` subclass must be added
#: here in the same change (``test_errors.py`` scans the package for strays).
_LAZY_ERRORS: dict[str, tuple[str, str]] = {
    "CatalogScanError": ("rebrew.coff_reloc", "CatalogScanError"),
    "ComponentError": ("rebrew.plugin", "ComponentError"),
    "ConfigError": ("rebrew.config", "ConfigError"),
    "ConfigKeyError": ("rebrew.config", "ConfigKeyError"),
    "ConfigNotFoundError": ("rebrew.config", "ConfigNotFoundError"),
    "DecompmeError": ("rebrew.decompme", "DecompmeError"),
    "Delphi16Error": ("rebrew.delphi16", "Delphi16Error"),
    "DosboxError": ("rebrew.dosbox", "DosboxError"),
    "LibraryOverrideError": ("rebrew.metadata", "LibraryOverrideError"),
    "McpApplyAborted": ("rebrew.ghidra.client", "McpApplyAborted"),
    "McpError": ("rebrew.ghidra.client", "McpError"),
    "MetadataValidationError": ("rebrew.metadata_model", "MetadataValidationError"),
    "Msvc16Error": ("rebrew.msvc16", "Msvc16Error"),
    "NeParseError": ("rebrew.ne_loader", "NeParseError"),
    "NoDecompilationError": ("rebrew.struct_recover", "NoDecompilationError"),
    "NotLzexeError": ("rebrew.lzexe", "NotLzexeError"),
    "Omf16Error": ("rebrew.omf16", "Omf16Error"),
    "OrphanInventoryError": ("rebrew.orphans", "OrphanInventoryError"),
    "RecompileError": ("rebrew.recompile_client", "RecompileError"),
    "RegistryError": ("rebrew.registry", "RegistryError"),
    "Tc16Error": ("rebrew.tc16", "Tc16Error"),
    "ToolchainError": ("rebrew.toolchain", "ToolchainError"),
    "UnresolvedSymbolError": ("rebrew.coff_reloc", "UnresolvedSymbolError"),
    "WorkspaceNotFound": ("rebrew.workspace.config", "WorkspaceNotFound"),
}


def __getattr__(name: str) -> object:
    if name in _LAZY_ERRORS:
        mod_name, attr_name = _LAZY_ERRORS[name]
        import importlib

        mod = importlib.import_module(mod_name)
        val: object = getattr(mod, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + list(_LAZY_ERRORS.keys()))


__all__ = ["RebrewError"]
