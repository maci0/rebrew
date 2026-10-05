"""compile_context: the declarations document a compile is pinned to.

Model and loader for ``--context``: :class:`CompileContext` carries the text
``compile`` prepends to a unit and its digest, which ``test``/``verify``
record beside a verdict.  ``rebrew export context`` (``rebrew.context``) produces
the document.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

#: Name a compile unit gives the context's declarations when they are merged
#: into the source (``compile.contextualized_source``), and the name the
#: generated document gives itself.  One constant, so the two cannot drift.
CONTEXT_UNIT_NAME = "ctx.c"


@dataclass(frozen=True)
class CompileContext:
    """The project-supplied types/prototypes a compile is pinned to.

    Attributes:
        path: File the context was read from.
        text: Exact text the compile prepends (empty means "no declarations",
            which leaves the compile unit and its cache key unchanged).
        sha256: Hex digest of ``text``, encoding with
            ``errors="surrogateescape"``.  A legacy-encoded context is read
            the same way, so the digest covers the file's original bytes and
            a context the loader could not decode still pins a compile
            instead of erroring.  Recorded beside a compile verdict so a
            stored result names the context it was earned under; a changed
            digest is a different compile input, not a still-valid match.
    """

    path: Path
    text: str
    sha256: str


def context_sha256(text: str) -> str:
    """SHA-256 hex digest of a context document.

    Encodes with ``errors="surrogateescape"``, the same scheme
    :func:`load_compile_context` decodes with, so the read/write pair is
    lossless for a legacy-encoded context and the digest names the bytes the
    compile consumed.  A strict ``encode("utf-8")`` raised
    ``UnicodeEncodeError`` on the surrogates such a read produces, which
    callers cannot turn into a stored result.
    """
    return hashlib.sha256(text.encode("utf-8", errors="surrogateescape")).hexdigest()


def load_compile_context(path: Path | None) -> CompileContext | None:
    """Read *path* as the compile context, or return ``None``.

    ``None`` only when *path* is ``None`` (no context asked for).  A file
    that exists but holds nothing yields a :class:`CompileContext` with an
    empty ``text``: its digest still pins "a context was supplied and it was
    empty", while the compile unit stays byte-identical to the bare source.

    Raises:
        FileNotFoundError: the named file does not exist.  An explicit
            ``--context`` that points nowhere must fail loud rather than
            silently compile without the context the user asked for.
    """
    if path is None:
        return None
    text = path.read_text(encoding="utf-8", errors="surrogateescape")
    return CompileContext(path=path, text=text, sha256=context_sha256(text))
