"""The placeholder-name rule: names a tool generated rather than a person chose.

One rule serves every consumer: BinSync import (a placeholder never overwrites
a chosen name), lint W023 and the default-name recommendation, the dependency
graph's focus lookup, and, through the ``rebrew.vocabulary`` op, the relumea
backend.
"""

from __future__ import annotations

import re

#: A name is a placeholder when the whole name matches. Prefixes are
#: case-sensitive, spelled as their generators emit them; hex digits take either
#: case:
#:
#: - empty: no name at all;
#: - ``fcn``, ``fn``, ``fun``: bare default names;
#: - ``FUN_``, ``DAT_``, ``thunk_``, ``switchdata`` followed by anything: Ghidra's
#:   generated labels, including thunks named after their target;
#: - ``FUN_``, ``func_``, ``sub_``, ``fcn_`` followed by hex, optionally with a
#:   leading ``_`` or ``@`` and a trailing ``@N`` / ``@@N`` decoration: Ghidra,
#:   rebrew and IDA function labels;
#: - ``fcn.<hex>``: rebrew's catalog label for a discovered function;
#: - ``g_`` and 4 to 8 hex digits: rebrew's synthetic global;
#: - ``fn_0x<hex>``, optionally followed by ``_`` and anything: the dependency
#:   graph's node for an unnamed call target.
#:
#: The pattern uses only syntax Python ``re`` and RE2 read alike, so clients
#: compile the string unchanged.
PLACEHOLDER_NAME_PATTERN = (
    r"^(?:"
    r"|fcn|fn|fun"
    r"|(?:FUN|DAT|thunk)_.*|switchdata.*"
    r"|@?_?(?:FUN|func|sub|fcn)_[0-9A-Fa-f]+(?:@@?[0-9]+)?"
    r"|fcn\.[0-9A-Fa-f]+"
    r"|g_[0-9A-Fa-f]{4,8}"
    r"|fn_0x[0-9A-Fa-f]+(?:_.*)?"
    r")$"
)

_PLACEHOLDER_NAME_RE = re.compile(PLACEHOLDER_NAME_PATTERN)


def is_placeholder_name(name: str) -> bool:
    """True when *name* is empty or a generated label (:data:`PLACEHOLDER_NAME_PATTERN`)."""
    return _PLACEHOLDER_NAME_RE.fullmatch(name) is not None
