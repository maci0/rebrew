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


__all__ = ["RebrewError"]
