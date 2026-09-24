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

``retryable`` is the one field the base carries, because "may I try this
again?" is the question every caller asks and the answer must not depend on
which subclass arrived.  It defaults to ``False`` (not retryable); the
subclasses that can tell transient from permanent (``ToolchainError``,
``RecompileError``, ``McpError``) set it per instance.  Domain fields
(``kind``, ``name``, ``status_code``, ``group``) stay on the subclass that
can actually fill them.
"""

from __future__ import annotations


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


_LAZY_ERRORS: dict[str, tuple[str, str]] = {
    "ConfigError": ("rebrew.config", "ConfigError"),
    "ConfigNotFoundError": ("rebrew.config", "ConfigNotFoundError"),
    "ConfigKeyError": ("rebrew.config", "ConfigKeyError"),
    "DecompmeError": ("rebrew.decompme", "DecompmeError"),
    "McpApplyAborted": ("rebrew.ghidra.client", "McpApplyAborted"),
    "McpError": ("rebrew.ghidra.client", "McpError"),
    "MetadataValidationError": ("rebrew.metadata_model", "MetadataValidationError"),
    "RecompileError": ("rebrew.recompile_client", "RecompileError"),
    "RegistryError": ("rebrew.registry", "RegistryError"),
    "ToolchainError": ("rebrew.toolchain", "ToolchainError"),
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
