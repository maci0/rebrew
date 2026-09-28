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
consumer never has to know which submodule defines which error.  The
``kind`` aliases that type those subclasses' ``kind`` field
(``ToolchainErrorKind`` and friends) come from the same place, because
annotating an ``exc.kind`` branch needs the alias too.  The classes
load on first attribute access, keeping ``import rebrew.errors`` free of the
compile stack.  ``__all__`` names every one of them, so a star-import or a
docs generator sees the same set this module documents.

``retryable`` is the one field the base carries, because "may I try this
again?" is the question every caller asks and the answer must not depend on
which subclass arrived.  It defaults to ``False`` (not retryable); the
subclasses that can tell transient from permanent (``ToolchainError``,
``RecompileError``, ``McpError``) set it per instance.  The domain fields
(``kind``, ``name``, ``status_code``, ``group``) default to ``None`` here and
are filled by the subclass that can: a consumer branching on ``exc.kind``
under one ``except RebrewError`` reads a field that is always present, and
reads ``None`` when this error carries no domain data (a
:class:`CompareResultError`, a rebuilt error of a type this build does not
know).  :meth:`RebrewError.to_dict` omits a field whose value is ``None``, so
the defaults do not add empty keys to a serialized error.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

# Same names ``__getattr__`` loads at runtime.  Present here so a type
# checker sees ``from rebrew.errors import ConfigError`` as that class.
if TYPE_CHECKING:
    from rebrew.coff_reloc import CatalogScanError as CatalogScanError
    from rebrew.coff_reloc import UnresolvedSymbolError as UnresolvedSymbolError
    from rebrew.compile import CompareResultError as CompareResultError
    from rebrew.config import ConfigError as ConfigError
    from rebrew.config import ConfigKeyError as ConfigKeyError
    from rebrew.config import ConfigNotFoundError as ConfigNotFoundError
    from rebrew.coverage_toml import CoverageTomlError as CoverageTomlError
    from rebrew.decompme import DecompmeError as DecompmeError
    from rebrew.decompme import DecompmeErrorKind as DecompmeErrorKind
    from rebrew.delphi16 import Delphi16Error as Delphi16Error
    from rebrew.doctor import LibIndexUnavailable as LibIndexUnavailable
    from rebrew.dosbox import DosboxError as DosboxError
    from rebrew.fingerprints import FingerprintError as FingerprintError
    from rebrew.ghidra.client import McpApplyAborted as McpApplyAborted
    from rebrew.ghidra.client import McpError as McpError
    from rebrew.ghidra.client import McpErrorKind as McpErrorKind
    from rebrew.lzexe import NotLzexeError as NotLzexeError
    from rebrew.matcher.scoring import SimilarityUnavailable as SimilarityUnavailable
    from rebrew.metadata import LibraryOverrideError as LibraryOverrideError
    from rebrew.metadata_model import MetadataValidationError as MetadataValidationError
    from rebrew.msvc16 import Msvc16Error as Msvc16Error
    from rebrew.ne_loader import NeParseError as NeParseError
    from rebrew.omf16 import Omf16Error as Omf16Error
    from rebrew.orphans import OrphanInventoryError as OrphanInventoryError
    from rebrew.plugin import ComponentError as ComponentError
    from rebrew.recompile_client import RecompileError as RecompileError
    from rebrew.recompile_client import RecompileErrorKind as RecompileErrorKind
    from rebrew.registry import RegistryError as RegistryError
    from rebrew.rename_ops import RenameError as RenameError
    from rebrew.residue import ResidueError as ResidueError
    from rebrew.security_scan import SecurityScanUnavailable as SecurityScanUnavailable
    from rebrew.struct_recover import NoDecompilationError as NoDecompilationError
    from rebrew.tc16 import Tc16Error as Tc16Error
    from rebrew.toolchain import ToolchainError as ToolchainError
    from rebrew.toolchain import ToolchainErrorKind as ToolchainErrorKind
    from rebrew.workspace.config import WorkspaceConfigError as WorkspaceConfigError
    from rebrew.workspace.config import WorkspaceNotFound as WorkspaceNotFound


def _blank_error(target: type[RebrewError], message: str) -> RebrewError:
    """Allocate *target* without running any ``__init__`` in its MRO.

    ``target.__new__(target)`` is the direct route and works for every class
    whose first ``__new__`` in the MRO matches its own layout.  A class that
    mixes exception bases breaks that route: ``ConfigNotFoundError`` is both
    a ``ConfigError`` (hence ``ValueError``) and a ``FileNotFoundError``, so
    the lookup reaches ``ValueError.__new__`` — a ``BaseException`` allocator
    — which refuses the extended ``OSError`` layout outright.  ``OSError.__new__``
    is the allocator that owns that layout and accepts any exception subclass,
    so it is the fallback.
    """
    try:
        exc: RebrewError = target.__new__(target)
    except TypeError:
        exc = OSError.__new__(target)
    BaseException.__init__(exc, message)
    return exc


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

    #: Domain fields, declared here so ``exc.kind`` and friends are readable
    #: on any :class:`RebrewError` and type-check without a ``getattr``
    #: default.  ``None`` means "this error carries no value for it"; only
    #: the subclasses that can fill a field do, and :meth:`to_dict` omits
    #: the ones left at ``None``.
    kind: str | None = None
    name: str | None = None
    status_code: int | None = None
    group: str | None = None

    #: Structured attributes a subclass may set, serialized by
    #: :meth:`to_dict`.  Every one is optional: an error that cannot fill a
    #: field simply omits it from the payload.
    _STRUCTURED_FIELDS: tuple[str, ...] = ("kind", "name", "status_code", "group")

    def to_dict(self) -> dict[str, Any]:
        """Serialize the error's structured fields into a JSON-safe dict.

        The point is that a consumer can persist a failure and still branch
        on it afterwards.  ``type`` names the class, ``message`` is ``str(exc)``,
        ``retryable`` is the decision the caller needs, and whichever of
        :attr:`_STRUCTURED_FIELDS` the instance carries come along (a
        ``RecompileError`` brings ``kind`` and ``status_code``).

        :meth:`from_dict` reads the payload back, so the round trip preserves
        ``kind`` / ``retryable`` / ``status_code`` without a consumer
        re-implementing this mapping.
        """
        payload: dict[str, Any] = {
            "type": type(self).__name__,
            "message": str(self),
            "retryable": bool(self.retryable),
        }
        for field_name in self._STRUCTURED_FIELDS:
            value = getattr(self, field_name, None)
            if value is not None:
                payload[field_name] = value
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RebrewError:
        """Rebuild the error :meth:`to_dict` wrote, keyed by its ``type``.

        The subclass is looked up in this module's export table, so a
        round-tripped ``RecompileError`` is a ``RecompileError`` again and
        ``isinstance`` keeps working on a result read back from JSON.  A
        ``type`` this build does not know (a newer rebrew wrote it, or the
        payload is foreign) yields a base :class:`RebrewError` carrying the
        same fields rather than raising: the message and the structured data
        survive, only the specific class does not.

        Instances are built with :func:`_blank_error` + ``BaseException.__init__``
        and their attributes assigned, because subclasses take differing
        constructor keywords and an unknown future subclass must not make a
        stored error unreadable.  Called on a subclass rather than on
        :class:`RebrewError`, it builds that class whatever ``type`` says.
        """
        type_name = data.get("type")
        rebuilt = _rebuilt_error_class(type_name)
        target: type[RebrewError] = rebuilt if rebuilt is not None else RebrewError
        if cls is not RebrewError:
            target = cls
        exc = _blank_error(target, str(data.get("message", "")))
        for key, value in data.items():
            if key not in ("type", "message"):
                setattr(exc, str(key), value)
        return exc


#: Every public error class in the package, keyed by the name a consumer
#: imports from ``rebrew.errors``.  A new ``RebrewError`` subclass must be added
#: here in the same change (``test_errors.py`` scans the package for strays).
_LAZY_ERRORS: dict[str, tuple[str, str]] = {
    "CatalogScanError": ("rebrew.coff_reloc", "CatalogScanError"),
    "ComponentError": ("rebrew.plugin", "ComponentError"),
    "CompareResultError": ("rebrew.compile", "CompareResultError"),
    "ConfigError": ("rebrew.config", "ConfigError"),
    "ConfigKeyError": ("rebrew.config", "ConfigKeyError"),
    "ConfigNotFoundError": ("rebrew.config", "ConfigNotFoundError"),
    "DecompmeError": ("rebrew.decompme", "DecompmeError"),
    "Delphi16Error": ("rebrew.delphi16", "Delphi16Error"),
    "DosboxError": ("rebrew.dosbox", "DosboxError"),
    "FingerprintError": ("rebrew.fingerprints", "FingerprintError"),
    "LibraryOverrideError": ("rebrew.metadata", "LibraryOverrideError"),
    "LibIndexUnavailable": ("rebrew.doctor", "LibIndexUnavailable"),
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
    "RenameError": ("rebrew.rename_ops", "RenameError"),
    "ResidueError": ("rebrew.residue", "ResidueError"),
    "SecurityScanUnavailable": ("rebrew.security_scan", "SecurityScanUnavailable"),
    "SimilarityUnavailable": ("rebrew.matcher.scoring", "SimilarityUnavailable"),
    "Tc16Error": ("rebrew.tc16", "Tc16Error"),
    "ToolchainError": ("rebrew.toolchain", "ToolchainError"),
    "UnresolvedSymbolError": ("rebrew.coff_reloc", "UnresolvedSymbolError"),
    "CoverageTomlError": ("rebrew.coverage_toml", "CoverageTomlError"),
    "WorkspaceConfigError": ("rebrew.workspace.config", "WorkspaceConfigError"),
    "WorkspaceNotFound": ("rebrew.workspace.config", "WorkspaceNotFound"),
}


#: The ``kind`` vocabularies, keyed by the name a consumer imports from
#: ``rebrew.errors``.  They sit beside the classes in :data:`_LAZY_ERRORS`
#: because branching on ``exc.kind`` (the documented alternative to matching
#: the message) needs the alias that types the field, and the consumer should
#: not have to know that ``RecompileErrorKind`` lives in ``rebrew.recompile_client``.
_LAZY_ERROR_KINDS: dict[str, tuple[str, str]] = {
    "DecompmeErrorKind": ("rebrew.decompme", "DecompmeErrorKind"),
    "McpErrorKind": ("rebrew.ghidra.client", "McpErrorKind"),
    "RecompileErrorKind": ("rebrew.recompile_client", "RecompileErrorKind"),
    "ToolchainErrorKind": ("rebrew.toolchain", "ToolchainErrorKind"),
}


def _rebuilt_error_class(type_name: object) -> type[RebrewError] | None:
    """Resolve a serialized ``type`` back to its class, or ``None`` if unknown.

    Lazy, like :data:`_LAZY_ERRORS` itself: reading a stored error must not
    import every error-defining module in the package.
    """
    if not isinstance(type_name, str):
        return None
    location = _LAZY_ERRORS.get(type_name)
    if location is None:
        return None
    import importlib

    klass = getattr(importlib.import_module(location[0]), location[1])
    return klass if isinstance(klass, type) and issubclass(klass, RebrewError) else None


def __getattr__(name: str) -> object:
    if name in _LAZY_ERRORS:
        mod_name, attr_name = _LAZY_ERRORS[name]
        import importlib

        mod = importlib.import_module(mod_name)
        val: object = getattr(mod, attr_name)
        globals()[name] = val
        return val
    if name in _LAZY_ERROR_KINDS:
        mod_name, attr_name = _LAZY_ERROR_KINDS[name]
        import importlib

        mod = importlib.import_module(mod_name)
        val = getattr(mod, attr_name)
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(
        list(globals().keys()) + list(_LAZY_ERRORS.keys()) + list(_LAZY_ERROR_KINDS.keys())
    )


__all__ = [
    "CatalogScanError",
    "CompareResultError",
    "ComponentError",
    "ConfigError",
    "ConfigKeyError",
    "ConfigNotFoundError",
    "CoverageTomlError",
    "DecompmeError",
    "DecompmeErrorKind",
    "Delphi16Error",
    "DosboxError",
    "FingerprintError",
    "LibraryOverrideError",
    "LibIndexUnavailable",
    "McpApplyAborted",
    "McpError",
    "McpErrorKind",
    "MetadataValidationError",
    "Msvc16Error",
    "NeParseError",
    "NoDecompilationError",
    "NotLzexeError",
    "Omf16Error",
    "OrphanInventoryError",
    "RebrewError",
    "RecompileError",
    "RecompileErrorKind",
    "RegistryError",
    "RenameError",
    "ResidueError",
    "SecurityScanUnavailable",
    "SimilarityUnavailable",
    "Tc16Error",
    "ToolchainError",
    "ToolchainErrorKind",
    "UnresolvedSymbolError",
    "WorkspaceConfigError",
    "WorkspaceNotFound",
]
