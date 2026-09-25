"""normalize_sdist.py – Rewrite an sdist or wheel so its bytes depend only on content.

setuptools copies each file's mtime, mode, and owner into the sdist tar, and
copies each source file's mode into the wheel zip.  Git stores only the
executable bit, so the other bits follow the checkout umask: umask 002 yields
0664 wheel entries and umask 022 yields 0644.  ``RECORD`` is hardcoded to
0664.  This rewrites both archives in place.  File contents are untouched.

Sdists: entries sorted by name, mtime set to ``SOURCE_DATE_EPOCH``, owner
``0:0`` with no names, mode ``0644`` (``0755`` for directories), and a gzip
header with no timestamp or file name.

Wheels: entries sorted by name, mtime set to ``SOURCE_DATE_EPOCH`` (clamped
to 1980, the ZIP epoch, the same clamp setuptools uses), mode ``0644``.
``RECORD`` hashes cover file bytes, not zip metadata, so they stay valid.

Usage::

    SOURCE_DATE_EPOCH=... uv run --no-project --offline \\
        python tools/normalize_sdist.py dist/*.tar.gz dist/*.whl
    make build   # runs this after ``uv build``
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
import stat
import tarfile
import time
import zipfile
from pathlib import Path

_EXEC_MODE = 0o755
_FILE_MODE = 0o644
# ZIP local headers cannot store dates before 1980-01-01 UTC.
_ZIP_EPOCH_FLOOR = 315532800
_ZIP_COMPRESS_LEVEL = 6
# create_system 3 marks external_attr as a Unix mode.  Pin it so the bytes
# do not depend on whether the normalizer itself ran on Windows.
_ZIP_CREATE_UNIX = 3


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


def _zip_date(epoch: int) -> tuple[int, int, int, int, int, int]:
    stamped = time.gmtime(max(epoch, _ZIP_EPOCH_FLOOR))
    return (
        stamped.tm_year,
        stamped.tm_mon,
        stamped.tm_mday,
        stamped.tm_hour,
        stamped.tm_min,
        stamped.tm_sec,
    )


def normalize_wheel(path: Path, epoch: int) -> None:
    """Rewrite the wheel at *path* with sorted entries, fixed mtimes, and mode 0644."""
    with zipfile.ZipFile(path) as src:
        entries = [(info.filename, src.read(info.filename)) for info in src.infolist()]
    entries.sort(key=lambda item: item[0])
    date_time = _zip_date(epoch)
    tmp = path.with_name(path.name + ".norm")
    try:
        with zipfile.ZipFile(
            tmp,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=_ZIP_COMPRESS_LEVEL,
        ) as dst:
            for name, data in entries:
                is_dir = name.endswith("/")
                info = zipfile.ZipInfo(filename=name, date_time=date_time)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = _ZIP_CREATE_UNIX
                kind = stat.S_IFDIR if is_dir else stat.S_IFREG
                mode = _EXEC_MODE if is_dir else _FILE_MODE
                info.external_attr = (kind | mode) << 16
                payload = b"" if is_dir else data
                dst.writestr(
                    info,
                    payload,
                    compress_type=zipfile.ZIP_DEFLATED,
                    compresslevel=_ZIP_COMPRESS_LEVEL,
                )
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def main() -> None:
    """Normalize every sdist or wheel named on the command line."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "artifacts",
        nargs="+",
        type=Path,
        help="sdist .tar.gz or wheel .whl files to rewrite",
    )
    args = parser.parse_args()
    epoch_text = os.environ.get("SOURCE_DATE_EPOCH")
    if not epoch_text or not epoch_text.isdigit():
        raise SystemExit("SOURCE_DATE_EPOCH must be set to a non-negative integer")
    epoch = int(epoch_text)
    for artifact in args.artifacts:
        if artifact.name.endswith(".whl"):
            normalize_wheel(artifact, epoch)
        elif artifact.name.endswith(".tar.gz"):
            normalize(artifact, epoch)
        else:
            raise SystemExit(f"expected a .tar.gz sdist or a .whl, got {artifact}")


if __name__ == "__main__":
    main()
