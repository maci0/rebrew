"""compression.py — the max-effort precompress the build-once output paths share.

Two commands emit static assets that are compressed once and then served or
shipped as-is: ``rebrew coverage report`` writes ``.gz`` / ``.zst`` sidecars next to its
HTML, and the dashboard precompresses its shell and ``/app.js`` at import.  Both want maximum effort (the body is built once, so the CPU is
spent once) and both drop the result when it does not shrink the payload, so
one function serves both instead of each keeping its own levels and its own
size check.

``zstandard`` is imported at the call, not at module scope: ``report`` is a CLI
component and pays nothing for a codec the caller may never reach.
"""

from __future__ import annotations

import gzip
from typing import Literal

#: Max effort for build-once static assets.  The dashboard's per-request
#: bodies are cheaper by design and keep their own levels.
GZIP_PRECOMPRESS_LEVEL = 9
ZSTD_PRECOMPRESS_LEVEL = 19

WireEncoding = Literal["zstd", "gzip"]


def precompress(raw: bytes, encoding: WireEncoding) -> bytes | None:
    """Return the max-effort *encoding* of *raw*, or ``None`` if it does not shrink.

    Gzip ``mtime=0`` so the bytes depend only on *raw*.  A dashboard ETag is
    the uncompressed hash, so a restarted process must not serve a different
    gzip body under that same tag; the same reasoning keeps a ``report``
    sidecar byte-identical across rebuilds.
    """
    if encoding == "zstd":
        import zstandard

        compressed = zstandard.ZstdCompressor(level=ZSTD_PRECOMPRESS_LEVEL).compress(raw)
    else:
        compressed = gzip.compress(raw, compresslevel=GZIP_PRECOMPRESS_LEVEL, mtime=0)
    return compressed if len(compressed) < len(raw) else None


__all__ = [
    "GZIP_PRECOMPRESS_LEVEL",
    "ZSTD_PRECOMPRESS_LEVEL",
    "WireEncoding",
    "precompress",
]
