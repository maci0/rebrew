"""normalize_sdist.py – Rewrite an sdist so its bytes depend only on content.

setuptools copies each file's mtime, mode, and owner into the sdist tar, so
two checkouts of one commit (different clone time, umask, or user) yield
different archives.  This rewrites the ``.tar.gz`` in place: entries sorted
by name, mtime set to ``SOURCE_DATE_EPOCH``, owner ``0:0`` with no names,
mode ``0644`` (``0755`` for directories), and a gzip header
with no timestamp or file name.  File contents are untouched.

Usage::

    SOURCE_DATE_EPOCH=... uv run --no-project --offline python tools/normalize_sdist.py dist/*.tar.gz
    make build   # runs this after ``uv build``
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import tarfile
from pathlib import Path

_EXEC_MODE = 0o755
_FILE_MODE = 0o644


def normalize(path: Path, epoch: int) -> None:
    """Rewrite the sdist at *path* with deterministic tar and gzip metadata."""
    with tarfile.open(path, "r:gz") as src:
        entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
        for member in sorted(src.getmembers(), key=lambda m: m.name):
            fileobj = src.extractfile(member) if member.isfile() else None
            entries.append((member, fileobj.read() if fileobj is not None else None))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as dst:
        for member, data in entries:
            member.mtime = epoch
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.mode = _EXEC_MODE if member.isdir() else _FILE_MODE
            member.pax_headers = {}
            dst.addfile(member, io.BytesIO(data) if data is not None else None)
    with path.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz:
        gz.write(buf.getvalue())


def main() -> None:
    """Normalize every sdist named on the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("sdists", nargs="+", type=Path, help="sdist .tar.gz files to rewrite")
    args = parser.parse_args()
    epoch_text = os.environ.get("SOURCE_DATE_EPOCH")
    if not epoch_text or not epoch_text.isdigit():
        raise SystemExit("SOURCE_DATE_EPOCH must be set to a non-negative integer")
    for sdist in args.sdists:
        normalize(sdist, int(epoch_text))


if __name__ == "__main__":
    main()
