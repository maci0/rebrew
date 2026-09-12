"""pragmas.py — identifier-level `#pragma` mutation operators.

MSVC6 codegen-control pragmas (optimize/intrinsic/check_stack/auto_inline)
inserted or removed around a function to shift register allocation and
inlining decisions.
"""

from __future__ import annotations

import random
import re

#: Letters the ``#pragma optimize`` directive accepts (MSVC 6+): a = assume no
#: aliasing, g = global optimizations, s/t = favor size/speed, y = frame-pointer
#: omission; the empty string turns everything off (or resets to the /O
#: baseline with on).
_OPTIMIZE_PRAGMA_RE = re.compile(
    r'^[ \t]*#pragma[ \t]+optimize\(\s*"[agsty]*"\s*,\s*(?:on|off)\s*\)[ \t]*$',
    re.MULTILINE,
)

#: MSVC library functions with intrinsic forms that change codegen when
#: inlined (memcpy → rep movs, memset → rep stos, strlen → repne scasb …).
_INTRINSIC_PRAGMA_SET = (
    "memcmp",
    "memcpy",
    "memset",
    "strcmp",
    "strcpy",
    "strlen",
    "abs",
    "labs",
    "fabs",
)

_INTRINSIC_PRAGMA_RE = re.compile(r"^[ \t]*#pragma[ \t]+intrinsic\([^)]*\)[ \t]*$", re.MULTILINE)

_CHECK_STACK_PRAGMA_RE = re.compile(
    r"^[ \t]*#pragma[ \t]+check_stack\(\s*off\s*\)[ \t]*$", re.MULTILINE
)


def mut_add_optimize_pragma(s: str, rng: random.Random) -> str | None:
    """Wrap the function in ``#pragma optimize("X", on|off)`` … ``("", on)``.

    ``#pragma optimize("", off)`` is the classic binary-matching lever: it
    disables all of a/g/s/t/y, forcing the unoptimized full-stack-frame layout
    (complete prologue, every local on the stack) that many original builds
    exhibit.  The other letters target one aspect each: ``"a"`` on drops the
    aliasing assumption, which lets the scheduler move a load across a store to
    the same object and is the only lever for a transposed field read/write
    pair; ``"y"`` off keeps the frame pointer, ``"g"`` off disables global
    optimizations, ``"s"``/``"t"`` on favor size/speed.  The closing
    ``("", on)`` resets to the /O-specified baseline.  No-op when a wrapper is
    already present.
    """
    if _OPTIMIZE_PRAGMA_RE.search(s):
        return None
    letter = rng.choice(("", "y", "g", "s", "t", "a"))
    mode = "on" if letter in ("s", "t", "a") else "off"
    return f'#pragma optimize("{letter}", {mode})\n{s}\n#pragma optimize("", on)\n'


def mut_remove_optimize_pragma(s: str, rng: random.Random) -> str | None:
    """Strip an existing ``#pragma optimize(...)`` wrapper (opening + reset)."""
    if not _OPTIMIZE_PRAGMA_RE.search(s):
        return None
    return _OPTIMIZE_PRAGMA_RE.sub("", s) or None


def mut_add_intrinsic_pragma(s: str, rng: random.Random) -> str | None:
    """Insert ``#pragma intrinsic(<crt fns>)`` before the function.

    With /Oi (included in /O2, /Ox, /O1) the listed library calls become
    inline instructions (memcpy → rep movs, memset → rep stos, strlen →
    repne scasb …) — a codegen lever for functions whose original was
    compiled with intrinsics.  Harmless for functions that call none of
    them.  No-op when already present.
    """
    if _INTRINSIC_PRAGMA_RE.search(s):
        return None
    return f"#pragma intrinsic({', '.join(_INTRINSIC_PRAGMA_SET)})\n{s}\n"


def mut_remove_intrinsic_pragma(s: str, rng: random.Random) -> str | None:
    """Strip an existing ``#pragma intrinsic(...)`` line."""
    if not _INTRINSIC_PRAGMA_RE.search(s):
        return None
    return _INTRINSIC_PRAGMA_RE.sub("", s) or None


def mut_toggle_check_stack_pragma(s: str, rng: random.Random) -> str | None:
    """Toggle ``#pragma check_stack(off)`` — suppresses /Gs stack probes.

    A target function with a large stack frame compiled WITHOUT probes needs
    the pragma; one with probes (or a small frame) does not.
    """
    if _CHECK_STACK_PRAGMA_RE.search(s):
        return _CHECK_STACK_PRAGMA_RE.sub("", s) or None
    return "#pragma check_stack(off)\n" + s + "\n"


_AUTO_INLINE_PRAGMA_RE = re.compile(
    r"^[ \t]*#pragma[ \t]+auto_inline\(\s*(?:on|off)\s*\)[ \t]*$",
    re.MULTILINE,
)


def mut_add_auto_inline_pragma(s: str, rng: random.Random) -> str | None:
    """Wrap the function in ``#pragma auto_inline(off)`` … ``("on")``.

    ``auto_inline(off)`` stops MSVC from automatically inlining functions
    **defined after the pragma** into their callers.  In the usual
    single-function compile the target has no callers, so the lever only
    bites when the same TU defines helper stubs the function calls (the
    classic DllMain shape: an entry point plus ``sub_XXXX`` shims) —
    without it MSVC inlines the helpers into the target, with it the
    calls stay ``call`` instructions.  The closing ``auto_inline(on)``
    restores auto-inlining for any following code.  No-op when a wrapper
    is already present.
    """
    if _AUTO_INLINE_PRAGMA_RE.search(s):
        return None
    return "#pragma auto_inline(off)\n" + s + "\n#pragma auto_inline(on)\n"


def mut_remove_auto_inline_pragma(s: str, rng: random.Random) -> str | None:
    """Strip an existing ``#pragma auto_inline(...)`` wrapper (open + close)."""
    if not _AUTO_INLINE_PRAGMA_RE.search(s):
        return None
    return _AUTO_INLINE_PRAGMA_RE.sub("", s) or None
